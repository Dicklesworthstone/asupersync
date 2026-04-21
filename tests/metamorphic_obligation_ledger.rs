//! Metamorphic Testing for Obligation Ledger Commit/Abort Idempotence
//!
//! Tests the invariants and safety properties of the obligation ledger's
//! commit and abort operations under various scenarios.
//!
//! Target: src/obligation/ledger.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Single Operation Invariant**: Each obligation can be resolved exactly once
//! 2. **Double Operation Rejection**: Attempting to resolve twice should panic consistently
//! 3. **State Consistency**: Final obligation state independent of duplicate resolution attempts
//! 4. **Statistics Monotonicity**: Ledger stats should only increment, never double-count
//! 5. **Temporal Invariance**: Resolution order doesn't affect final ledger consistency

#![cfg(test)]

use proptest::prelude::*;
use std::panic;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::obligation::ledger::{ObligationLedger, ObligationToken};
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};

/// Test harness for obligation ledger metamorphic testing
struct LedgerTestHarness {
    lab_runtime: LabRuntime,
    ledger: ObligationLedger,
}

impl LedgerTestHarness {
    fn new() -> Self {
        let config = LabConfig::default()
            .worker_count(1)
            .trace_capacity(512)
            .max_steps(1000);
        let lab_runtime = LabRuntime::new(config);
        let ledger = ObligationLedger::new();

        Self {
            lab_runtime,
            ledger,
        }
    }

    fn create_test_task(&self) -> TaskId {
        TaskId::new_for_test(1, 0)
    }

    fn create_test_region(&self) -> RegionId {
        RegionId::new_for_test(1, 0)
    }

    fn acquire_obligation(&mut self, kind: ObligationKind, time: Time) -> ObligationToken {
        let task = self.create_test_task();
        let region = self.create_test_region();
        self.ledger.acquire(kind, task, region, time)
    }

    fn acquire_multiple_obligations(
        &mut self,
        count: usize,
        start_time: Time,
    ) -> Vec<ObligationToken> {
        (0..count)
            .map(|i| {
                let time = Time::from_nanos(start_time.as_nanos() + i as u64);
                self.acquire_obligation(ObligationKind::Lease, time)
            })
            .collect()
    }
}

/// Statistics for analyzing ledger behavior
#[derive(Debug, Clone)]
struct LedgerOperationStats {
    initial_stats: asupersync::obligation::ledger::LedgerStats,
    final_stats: asupersync::obligation::ledger::LedgerStats,
    operations_attempted: usize,
    operations_succeeded: usize,
    operations_panicked: usize,
    unique_obligations: usize,
}

impl LedgerOperationStats {
    fn new(
        initial_stats: asupersync::obligation::ledger::LedgerStats,
        final_stats: asupersync::obligation::ledger::LedgerStats,
        operations_attempted: usize,
        operations_succeeded: usize,
        operations_panicked: usize,
        unique_obligations: usize,
    ) -> Self {
        Self {
            initial_stats,
            final_stats,
            operations_attempted,
            operations_succeeded,
            operations_panicked,
            unique_obligations,
        }
    }

    fn stats_increment_correctly(&self) -> bool {
        let expected_resolved = self.operations_succeeded;
        let actual_resolved = (self.final_stats.total_committed + self.final_stats.total_aborted)
            - (self.initial_stats.total_committed + self.initial_stats.total_aborted);
        expected_resolved == actual_resolved as usize
    }

    fn no_double_counting(&self) -> bool {
        // Each unique obligation should contribute exactly once to final counts
        let total_final_operations =
            self.final_stats.total_committed + self.final_stats.total_aborted;
        let total_initial_operations =
            self.initial_stats.total_committed + self.initial_stats.total_aborted;

        (total_final_operations - total_initial_operations) == self.unique_obligations as u64
    }
}

// MR1: Single Operation Invariant
// Each obligation can be resolved exactly once
#[test]
fn mr_single_operation_invariant() {
    proptest!(|(
        obligation_count in 1..10_usize,
        commit_count in 0..10_usize
    )| {
        let mut harness = LedgerTestHarness::new();
        let initial_stats = harness.ledger.stats();

        // Create obligations
        let tokens = harness.acquire_multiple_obligations(obligation_count, Time::ZERO);
        let token_ids: Vec<ObligationId> = tokens.iter().map(|t| t.id()).collect();

        // Commit some obligations
        let commit_tokens = tokens.into_iter().take(commit_count.min(obligation_count));
        for token in commit_tokens {
            harness.ledger.commit(token, Time::from_nanos(100));
        }

        // Abort remaining by ID
        for &id in token_ids.iter().skip(commit_count.min(obligation_count)) {
            harness.ledger.abort_by_id(id, Time::from_nanos(200), ObligationAbortReason::Cancel);
        }

        let final_stats = harness.ledger.stats();

        // Each obligation should be resolved exactly once
        prop_assert_eq!(final_stats.pending, initial_stats.pending);
        prop_assert_eq!(
            final_stats.total_committed + final_stats.total_aborted,
            initial_stats.total_committed + initial_stats.total_aborted + obligation_count as u64
        );

        // Verify all obligations have been resolved
        for &id in &token_ids {
            let record = harness.ledger.get(id);
            prop_assert!(record.is_some(), "Obligation {} should exist", id);
            let record = record.unwrap();
            prop_assert!(
                matches!(record.state, ObligationState::Committed | ObligationState::Aborted),
                "Obligation {} should be resolved, got state {:?}",
                id, record.state
            );
        }
    });
}

// MR2: Double Operation Rejection
// Attempting to resolve twice should panic consistently
#[test]
fn mr_double_operation_rejection() {
    proptest!(|(
        first_operation in prop::sample::select(vec!["commit", "abort"]),
        second_operation in prop::sample::select(vec!["commit_token", "abort_token", "abort_by_id"])
    )| {
        let mut harness = LedgerTestHarness::new();

        // Create two tokens for the same-ID test
        let token1 = harness.acquire_obligation(ObligationKind::Lease, Time::ZERO);
        let token2 = harness.acquire_obligation(ObligationKind::Lease, Time::from_nanos(10));
        let id1 = token1.id();
        let id2 = token2.id();

        // First operation - should succeed
        let first_result: Result<(), ()> = match first_operation {
            "commit" => {
                harness.ledger.commit(token1, Time::from_nanos(50));
                Ok(())
            }
            "abort" => {
                harness.ledger.abort(token1, Time::from_nanos(50), ObligationAbortReason::Cancel);
                Ok(())
            }
            _ => unreachable!(),
        };
        prop_assert!(first_result.is_ok(), "First operation should succeed");

        // Second operation on same obligation - should panic
        let second_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            match second_operation {
                "commit_token" => {
                    // This would fail anyway because token1 was consumed, but test abort_by_id
                    harness.ledger.abort_by_id(id1, Time::from_nanos(60), ObligationAbortReason::Cancel);
                }
                "abort_token" => {
                    harness.ledger.abort_by_id(id1, Time::from_nanos(60), ObligationAbortReason::Cancel);
                }
                "abort_by_id" => {
                    harness.ledger.abort_by_id(id1, Time::from_nanos(60), ObligationAbortReason::Cancel);
                }
                _ => unreachable!(),
            }
        }));

        prop_assert!(second_result.is_err(), "Double operation should panic");

        // Clean up second token to avoid leak
        harness.ledger.commit(token2, Time::from_nanos(70));

        // Verify ledger consistency after panic
        let stats = harness.ledger.stats();
        prop_assert_eq!(stats.pending, 0, "No obligations should remain pending");
        prop_assert_eq!(stats.total_leaked, 0, "No obligations should be leaked");
    });
}

// MR3: State Consistency
// Final obligation state independent of duplicate resolution attempts
#[test]
fn mr_state_consistency() {
    proptest!(|(
        commit_time in 0..1000_u64,
        duplicate_attempt_time in 0..2000_u64
    )| {
        let mut harness1 = LedgerTestHarness::new();
        let mut harness2 = LedgerTestHarness::new();

        // Scenario 1: Normal single commit
        let token1 = harness1.acquire_obligation(ObligationKind::Lease, Time::ZERO);
        let id1 = token1.id();
        harness1.ledger.commit(token1, Time::from_nanos(commit_time));
        let record1 = harness1.ledger.get(id1).unwrap();

        // Scenario 2: Commit followed by failed duplicate attempt
        let token2 = harness2.acquire_obligation(ObligationKind::Lease, Time::ZERO);
        let id2 = token2.id();
        harness2.ledger.commit(token2, Time::from_nanos(commit_time));

        // Attempt duplicate - should panic but not affect state
        let duplicate_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            harness2.ledger.abort_by_id(id2, Time::from_nanos(duplicate_attempt_time), ObligationAbortReason::Cancel);
        }));
        prop_assert!(duplicate_result.is_err(), "Duplicate should panic");

        let record2 = harness2.ledger.get(id2).unwrap();

        // Both scenarios should result in identical final state
        prop_assert_eq!(record1.state, record2.state, "States should be identical");
        prop_assert_eq!(record1.acquired_at, record2.acquired_at, "Acquire times should be identical");
        prop_assert_eq!(record1.resolved_at, record2.resolved_at, "Resolve times should be identical");

        // Stats should also be identical
        let stats1 = harness1.ledger.stats();
        let stats2 = harness2.ledger.stats();
        prop_assert_eq!(stats1, stats2, "Ledger stats should be identical");
    });
}

// MR4: Statistics Monotonicity
// Ledger stats should only increment, never double-count
#[test]
fn mr_statistics_monotonicity() {
    proptest!(|(
        operations in prop::collection::vec(
            prop::sample::select(vec!["commit", "abort"]),
            1..8
        )
    )| {
        let mut harness = LedgerTestHarness::new();
        let initial_stats = harness.ledger.stats();

        let mut tokens = Vec::new();
        for i in 0..operations.len() {
            tokens.push(harness.acquire_obligation(ObligationKind::Lease, Time::from_nanos(i as u64)));
        }

        let mut operations_succeeded = 0;
        let mut commit_count = 0;
        let mut abort_count = 0;

        // Execute operations
        for (token, operation) in tokens.into_iter().zip(operations.iter()) {
            match *operation {
                "commit" => {
                    harness.ledger.commit(token, Time::from_nanos(100));
                    operations_succeeded += 1;
                    commit_count += 1;
                }
                "abort" => {
                    harness.ledger.abort(token, Time::from_nanos(100), ObligationAbortReason::Cancel);
                    operations_succeeded += 1;
                    abort_count += 1;
                }
                _ => unreachable!(),
            }
        }

        let final_stats = harness.ledger.stats();

        // Statistics should increment monotonically
        prop_assert!(final_stats.total_acquired >= initial_stats.total_acquired);
        prop_assert!(final_stats.total_committed >= initial_stats.total_committed);
        prop_assert!(final_stats.total_aborted >= initial_stats.total_aborted);

        // Increments should match operations
        prop_assert_eq!(
            final_stats.total_committed - initial_stats.total_committed,
            commit_count,
            "Commit count should match operations"
        );
        prop_assert_eq!(
            final_stats.total_aborted - initial_stats.total_aborted,
            abort_count,
            "Abort count should match operations"
        );

        // Total resolved should equal operations
        let total_resolved = (final_stats.total_committed + final_stats.total_aborted)
            - (initial_stats.total_committed + initial_stats.total_aborted);
        prop_assert_eq!(total_resolved, operations_succeeded as u64);
    });
}

// MR5: Temporal Invariance
// Resolution order doesn't affect final ledger consistency
#[test]
fn mr_temporal_invariance() {
    proptest!(|(
        mut obligation_operations in prop::collection::vec(
            (prop::sample::select(vec!["commit", "abort"]), 0..1000_u64),
            2..6
        )
    )| {
        // Test both original order and shuffled order
        let original_operations = obligation_operations.clone();

        // Reverse the operations for second test (simple transformation)
        obligation_operations.reverse();

        // Convert &str to String for execute_obligation_sequence
        let original_ops: Vec<(String, u64)> = original_operations
            .iter()
            .map(|(op, time)| (op.to_string(), *time))
            .collect();
        let shuffled_ops: Vec<(String, u64)> = obligation_operations
            .iter()
            .map(|(op, time)| (op.to_string(), *time))
            .collect();

        // Execute both scenarios
        let result1 = execute_obligation_sequence(&original_ops);
        let result2 = execute_obligation_sequence(&shuffled_ops);

        // Final ledger state should be equivalent regardless of order
        prop_assert_eq!(
            result1.total_committed, result2.total_committed,
            "Total committed should be order-invariant"
        );
        prop_assert_eq!(
            result1.total_aborted, result2.total_aborted,
            "Total aborted should be order-invariant"
        );
        prop_assert_eq!(
            result1.pending, result2.pending,
            "Pending count should be order-invariant"
        );
        prop_assert_eq!(
            result1.total_leaked, result2.total_leaked,
            "Leaked count should be order-invariant"
        );
    });
}

fn execute_obligation_sequence(
    operations: &[(String, u64)],
) -> asupersync::obligation::ledger::LedgerStats {
    let mut harness = LedgerTestHarness::new();

    // Create all obligations first
    let mut tokens = Vec::new();
    for (i, _) in operations.iter().enumerate() {
        tokens.push(harness.acquire_obligation(ObligationKind::Lease, Time::from_nanos(i as u64)));
    }

    // Execute operations in the specified order
    for (token, (operation, time)) in tokens.into_iter().zip(operations.iter()) {
        match operation.as_str() {
            "commit" => {
                harness.ledger.commit(token, Time::from_nanos(*time));
            }
            "abort" => {
                harness.ledger.abort(
                    token,
                    Time::from_nanos(*time),
                    ObligationAbortReason::Cancel,
                );
            }
            _ => unreachable!(),
        }
    }

    harness.ledger.stats()
}
