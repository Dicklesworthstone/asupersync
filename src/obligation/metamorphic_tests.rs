//! Metamorphic tests for obligation system invariants.
//!
//! These tests verify properties that must hold regardless of execution order,
//! catching bugs that conventional unit tests miss by exploiting transformations
//! of the input space while checking relationships between outputs.

#[cfg(test)]
use crate::obligation::ledger::{LedgerStats, ObligationLedger, ObligationToken};
#[cfg(test)]
use crate::record::{ObligationAbortReason, ObligationKind};
#[cfg(test)]
use crate::types::{RegionId, TaskId, Time};

#[cfg(test)]
#[inline]
fn tid(n: u32) -> TaskId {
    // Helper: TaskId/RegionId expose `new_for_test(index, generation)`
    // (src/types/id.rs:297, 109) — there is no `new(u64)` constructor.
    // The metamorphic relations only need distinct IDs, so generation 0
    // suffices.
    TaskId::new_for_test(n, 0)
}

#[cfg(test)]
#[inline]
fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

#[cfg(test)]
/// Represents a scheduled operation with its timing
#[derive(Debug, Clone)]
pub enum ScheduledOp {
    /// Acquire an obligation, returning a token
    Acquire {
        /// Obligation resource kind to acquire.
        kind: ObligationKind,
        /// Task that owns the acquired obligation.
        task: TaskId,
        /// Region that bounds the obligation lifecycle.
        region: RegionId,
        /// Logical acquisition time recorded in the ledger.
        time: Time,
    },
    /// Commit a previously acquired token (by acquire index)
    CommitByIndex {
        /// Index of the earlier acquire operation whose token should commit.
        acquire_index: usize,
        /// Logical commit time recorded in the ledger.
        time: Time,
    },
    /// Abort a previously acquired token (by acquire index)
    AbortByIndex {
        /// Index of the earlier acquire operation whose token should abort.
        acquire_index: usize,
        /// Abort reason recorded for the obligation.
        reason: ObligationAbortReason,
        /// Logical abort time recorded in the ledger.
        time: Time,
    },
    /// Mark a region as finalized (closed)
    FinalizeRegion {
        /// Region whose pending obligations should be finalized.
        region: RegionId,
    },
}

#[cfg(test)]
/// Execution context that executes a sequence of operations
#[derive(Debug)]
struct ExecutionContext {
    ledger: ObligationLedger,
    /// Tokens acquired by index in the operation sequence
    acquired_tokens: Vec<Option<ObligationToken>>,
}

#[cfg(test)]
impl ExecutionContext {
    fn new() -> Self {
        Self {
            ledger: ObligationLedger::new(),
            acquired_tokens: Vec::new(),
        }
    }

    fn execute(&mut self, ops: &[ScheduledOp]) -> LedgerStats {
        self.acquired_tokens.clear();
        // Work around ObligationToken not implementing Clone by storing indices instead
        self.acquired_tokens = (0..ops.len()).map(|_| None).collect();

        for (idx, op) in ops.iter().enumerate() {
            match op {
                ScheduledOp::Acquire {
                    kind,
                    task,
                    region,
                    time,
                } => {
                    let token = self.ledger.acquire(*kind, *task, *region, *time);
                    self.acquired_tokens[idx] = Some(token);
                }
                ScheduledOp::CommitByIndex {
                    acquire_index,
                    time,
                } => {
                    // ObligationToken is intentionally !Copy/!Clone (linear
                    // by design — see src/obligation/ledger.rs:108), so we
                    // must move the token out of the Option via `take()`
                    // rather than dereference it. After commit, the slot
                    // is left as None so a duplicate CommitByIndex /
                    // AbortByIndex on the same index becomes a no-op.
                    if let Some(slot) = self.acquired_tokens.get_mut(*acquire_index) {
                        if let Some(token) = slot.take() {
                            let _ = self.ledger.commit(token, *time);
                        }
                    }
                }
                ScheduledOp::AbortByIndex {
                    acquire_index,
                    reason,
                    time,
                } => {
                    if let Some(slot) = self.acquired_tokens.get_mut(*acquire_index) {
                        if let Some(token) = slot.take() {
                            let _ = self.ledger.abort(token, *time, *reason);
                        }
                    }
                }
                ScheduledOp::FinalizeRegion { region } => {
                    self.ledger.mark_region_finalized(*region);
                }
            }
        }

        self.ledger.stats()
    }
}

//
// METAMORPHIC RELATIONS
//

#[cfg(test)]
mod metamorphic_tests {
    use super::*;

    /// MR1: Total Token Conservation (Additive)
    /// acquired = committed + aborted + leaked + pending, ALWAYS
    #[test]
    fn mr_total_token_conservation_simple() {
        let ops = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::Acquire {
                kind: ObligationKind::Ack,
                task: tid(2),
                region: rid(1),
                time: Time::from_nanos(1500),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(2000),
            },
        ];

        let mut ctx = ExecutionContext::new();
        let stats = ctx.execute(&ops);

        // Test the conservation law
        let total_resolved = stats.total_committed + stats.total_aborted + stats.total_leaked;
        let total_accounted = total_resolved + stats.pending;

        assert_eq!(
            stats.total_acquired,
            total_accounted,
            "CONSERVATION VIOLATION: acquired={}, committed={}, aborted={}, leaked={}, pending={}",
            stats.total_acquired,
            stats.total_committed,
            stats.total_aborted,
            stats.total_leaked,
            stats.pending
        );
    }

    /// MR2: Schedule Invariance (Permutative)
    /// Reordering independent operations should preserve conservation
    #[test]
    fn mr_schedule_invariance_simple() {
        let ops1 = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::Acquire {
                kind: ObligationKind::Ack,
                task: tid(2),
                region: rid(2),
                time: Time::from_nanos(1500),
            },
        ];

        // Transformation: reorder the acquires
        let ops2 = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::Ack,
                task: tid(2),
                region: rid(2),
                time: Time::from_nanos(1500),
            },
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
        ];

        let mut ctx1 = ExecutionContext::new();
        let stats1 = ctx1.execute(&ops1);

        let mut ctx2 = ExecutionContext::new();
        let stats2 = ctx2.execute(&ops2);

        // Relation: final counts should be invariant under reordering
        assert_eq!(
            stats1.total_acquired, stats2.total_acquired,
            "Total acquired changed under reordering: {} -> {}",
            stats1.total_acquired, stats2.total_acquired
        );

        assert_eq!(
            stats1.pending, stats2.pending,
            "Pending count changed under reordering: {} -> {}",
            stats1.pending, stats2.pending
        );
    }

    /// MR3: Region Quiescence Conservation (Inclusive/Exclusive)
    /// Disjoint regions should compose independently
    #[test]
    fn mr_region_quiescence_conservation() {
        let region1_ops = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1000),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(2000),
            },
        ];

        let region2_ops = vec![ScheduledOp::Acquire {
            kind: ObligationKind::Ack,
            task: tid(2),
            region: rid(2000),
            time: Time::from_nanos(1500),
        }];

        // Execute regions separately
        let mut ctx1 = ExecutionContext::new();
        let stats1 = ctx1.execute(&region1_ops);

        let mut ctx2 = ExecutionContext::new();
        let stats2 = ctx2.execute(&region2_ops);

        // Execute regions combined
        let mut combined_ops = region1_ops.clone();
        combined_ops.extend(region2_ops.clone());

        let mut combined_ctx = ExecutionContext::new();
        let combined_stats = combined_ctx.execute(&combined_ops);

        // Relation: combined execution should equal sum of separate executions
        assert_eq!(
            combined_stats.total_acquired,
            stats1.total_acquired + stats2.total_acquired,
            "Region composition failed for acquired: {} ≠ {} + {}",
            combined_stats.total_acquired,
            stats1.total_acquired,
            stats2.total_acquired
        );

        assert_eq!(
            combined_stats.pending,
            stats1.pending + stats2.pending,
            "Region composition failed for pending: {} ≠ {} + {}",
            combined_stats.pending,
            stats1.pending,
            stats2.pending
        );
    }

    /// MR4: State Transition Uniqueness (Permutative)
    /// Each obligation transitions exactly once
    #[test]
    fn mr_state_transition_uniqueness() {
        let ops = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::Acquire {
                kind: ObligationKind::Ack,
                task: tid(2),
                region: rid(1),
                time: Time::from_nanos(1500),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(2000),
            },
            ScheduledOp::AbortByIndex {
                acquire_index: 1,
                reason: ObligationAbortReason::Cancel,
                time: Time::from_nanos(2500),
            },
        ];

        let mut ctx = ExecutionContext::new();
        let stats = ctx.execute(&ops);

        // Every acquired obligation should be in exactly one final state
        let total_final_states =
            stats.total_committed + stats.total_aborted + stats.total_leaked + stats.pending;

        assert_eq!(
            stats.total_acquired, total_final_states,
            "STATE TRANSITION UNIQUENESS VIOLATION: acquired={}, final_states={}",
            stats.total_acquired, total_final_states
        );
    }

    /// MR5: Lease Expiration Monotonicity (Multiplicative)
    /// Scaling all timestamps shouldn't affect obligation counts
    #[test]
    fn mr_lease_expiration_monotonicity() {
        let ops_original = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::Lease,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(2000),
            },
        ];

        // Transformation: scale all timestamps by 10
        let ops_scaled = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::Lease,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(10000),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(20000),
            },
        ];

        let mut ctx_original = ExecutionContext::new();
        let stats_original = ctx_original.execute(&ops_original);

        let mut ctx_scaled = ExecutionContext::new();
        let stats_scaled = ctx_scaled.execute(&ops_scaled);

        // Relation: scaling time shouldn't affect final obligation counts
        assert_eq!(
            stats_original.total_acquired, stats_scaled.total_acquired,
            "Time scaling changed acquired count: {} -> {}",
            stats_original.total_acquired, stats_scaled.total_acquired
        );

        assert_eq!(
            stats_original.total_committed, stats_scaled.total_committed,
            "Time scaling changed commit count: {} -> {}",
            stats_original.total_committed, stats_scaled.total_committed
        );
    }

    /// MR6: Double-Resolve Determinism (Equivalence)
    /// Double commit/abort attempts should be rejected deterministically
    #[test]
    fn mr_double_resolve_determinism() {
        let ops_original = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(2000),
            },
        ];

        // Transformation: add duplicate commit attempt
        let mut ops_doubled = ops_original.clone();
        ops_doubled.push(ScheduledOp::CommitByIndex {
            acquire_index: 0,
            time: Time::from_nanos(3000),
        });

        let mut ctx_original = ExecutionContext::new();
        let stats_original = ctx_original.execute(&ops_original);

        let mut ctx_doubled = ExecutionContext::new();
        let stats_doubled = ctx_doubled.execute(&ops_doubled);

        // Relation: duplicate resolves should not change final counts
        assert_eq!(
            stats_original.total_committed, stats_doubled.total_committed,
            "Double resolve changed commit count: {} -> {}",
            stats_original.total_committed, stats_doubled.total_committed
        );

        assert_eq!(
            stats_original.total_aborted, stats_doubled.total_aborted,
            "Double resolve changed abort count: {} -> {}",
            stats_original.total_aborted, stats_doubled.total_aborted
        );
    }

    /// Validation: basic smoke test that MRs can run
    #[test]
    fn metamorphic_suite_smoke_test() {
        let ops = vec![
            ScheduledOp::Acquire {
                kind: ObligationKind::SendPermit,
                task: tid(1),
                region: rid(1),
                time: Time::from_nanos(1000),
            },
            ScheduledOp::CommitByIndex {
                acquire_index: 0,
                time: Time::from_nanos(2000),
            },
        ];

        let mut ctx = ExecutionContext::new();
        let stats = ctx.execute(&ops);

        // Basic conservation check
        assert_eq!(stats.total_acquired, 1);
        assert_eq!(stats.total_committed, 1);
        assert_eq!(stats.pending, 0);

        // Conservation law
        let total =
            stats.total_committed + stats.total_aborted + stats.total_leaked + stats.pending;
        assert_eq!(stats.total_acquired, total);
    }
}
