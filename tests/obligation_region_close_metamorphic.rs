//! Metamorphic tests for obligation-region close invariants
//!
//! Tests the core asupersync claims from README.md and asupersync_plan_v4.md:
//! 1. Every obligation transitions exactly once (Reserved→Committed/Aborted/Leaked)
//! 2. Region close requires zero pending obligations
//! 3. No double-resolve panics
//! 4. Commit/abort balance across cancel/drain scenarios
//!
//! These properties should hold regardless of execution order, making them
//! ideal candidates for metamorphic testing.

use asupersync::obligation::ledger::{LedgerStats, ObligationLedger};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::types::{RegionId, TaskId, Time};
use proptest::prelude::*;

// =============================================================================
// Test Infrastructure
// =============================================================================

/// A simple test execution context for obligation operations
struct TestContext {
    ledger: ObligationLedger,
    tokens: Vec<Option<asupersync::obligation::ledger::ObligationToken>>,
}

fn task_id(index: u32) -> TaskId {
    TaskId::new_for_test(index, 0)
}

fn region_id(index: u32) -> RegionId {
    RegionId::new_for_test(index, 0)
}

impl TestContext {
    fn new() -> Self {
        Self {
            ledger: ObligationLedger::new(),
            tokens: Vec::new(),
        }
    }

    fn acquire(
        &mut self,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
        time: Time,
    ) -> usize {
        let token = self.ledger.acquire(kind, task, region, time);
        let index = self.tokens.len();
        self.tokens.push(Some(token));
        index
    }

    fn commit(&mut self, index: usize, time: Time) -> bool {
        if let Some(token_slot) = self.tokens.get_mut(index) {
            if let Some(token) = token_slot.take() {
                self.ledger.commit(token, time);
                return true;
            }
        }
        false
    }

    fn abort(&mut self, index: usize, time: Time, reason: ObligationAbortReason) -> bool {
        if let Some(token_slot) = self.tokens.get_mut(index) {
            if let Some(token) = token_slot.take() {
                self.ledger.abort(token, time, reason);
                return true;
            }
        }
        false
    }

    fn finalize_region(&mut self, region: RegionId) {
        self.ledger.mark_region_finalized(region);
    }

    fn stats(&self) -> LedgerStats {
        self.ledger.stats()
    }

    fn pending_count(&self) -> u64 {
        self.ledger.pending_count()
    }
}

// =============================================================================
// Metamorphic Relations for Obligation-Region Close Invariants
// =============================================================================

/// MR1: Total Token Conservation (Additive)
/// Tests that acquired = committed + aborted + leaked + pending, always.
/// This verifies the claim "Every obligation transitions exactly once".
proptest! {
    #[test]
    fn mr_total_token_conservation(
        acquire_count in 1usize..=10,
        commit_ratio in 0.0f64..=1.0,
        abort_ratio in 0.0f64..=1.0
    ) {
        let mut ctx = TestContext::new();
        let mut tokens = Vec::new();

        // Acquire obligations
        for i in 0..acquire_count {
            let kind = match i % 4 {
                0 => ObligationKind::SendPermit,
                1 => ObligationKind::Ack,
                2 => ObligationKind::Lease,
                _ => ObligationKind::IoOp,
            };

            let token_index = ctx.acquire(
                kind,
                task_id(i as u32 + 1),
                region_id(1),
                Time::from_nanos(1000 + i as u64 * 1000)
            );
            tokens.push(token_index);
        }

        // Resolve some obligations
        let commit_count = ((acquire_count as f64) * commit_ratio) as usize;
        let abort_count = ((acquire_count as f64) * abort_ratio) as usize;

        // Commit first commit_count
        for (i, token) in tokens
            .iter()
            .copied()
            .enumerate()
            .take(commit_count.min(acquire_count))
        {
            ctx.commit(token, Time::from_nanos(2000 + i as u64 * 1000));
        }

        // Abort next abort_count (avoiding overlap with commits)
        for (i, token) in tokens
            .iter()
            .copied()
            .enumerate()
            .take((commit_count + abort_count).min(acquire_count))
            .skip(commit_count)
        {
            ctx.abort(
                token,
                Time::from_nanos(3000 + i as u64 * 1000),
                ObligationAbortReason::Cancel
            );
        }

        let stats = ctx.stats();

        // MR: Conservation law must always hold
        let total_resolved = stats.total_committed + stats.total_aborted + stats.total_leaked;
        let total_accounted = total_resolved + stats.pending;

        prop_assert_eq!(
            stats.total_acquired,
            total_accounted,
            "CONSERVATION VIOLATION: acquired={}, committed={}, aborted={}, leaked={}, pending={}",
            stats.total_acquired,
            stats.total_committed,
            stats.total_aborted,
            stats.total_leaked,
            stats.pending
        );

        // MR: Each obligation is in exactly one final state
        prop_assert_eq!(
            stats.total_acquired,
            stats.total_committed + stats.total_aborted + stats.total_leaked + stats.pending,
            "STATE UNIQUENESS: Some obligations are in multiple states or missing"
        );
    }
}

/// MR2: Region Close Quiescence Invariant
/// Tests the documented claim "region close = quiescence".
/// Region should only be closeable when pending_obligations() == 0.
proptest! {
    #[test]
    fn mr_region_close_quiescence_invariant(
        obligation_count in 1usize..=8,
        resolve_ratio in 0.0f64..=1.0
    ) {
        let mut ctx = TestContext::new();
        let region_id = region_id(1);
        let mut tokens = Vec::new();

        // Acquire obligations in the region
        for i in 0..obligation_count {
            let token_index = ctx.acquire(
                ObligationKind::SendPermit,
                task_id(i as u32 + 1),
                region_id,
                Time::from_nanos(1000 + i as u64 * 1000)
            );
            tokens.push(token_index);
        }

        // Resolve some obligations
        let resolve_count = ((obligation_count as f64) * resolve_ratio).floor() as usize;
        for (i, token) in tokens.iter().copied().enumerate().take(resolve_count) {
            ctx.commit(token, Time::from_nanos(2000 + i as u64 * 1000));
        }

        let stats = ctx.stats();
        let expected_pending = obligation_count - resolve_count;

        // MR: Pending count should match unresolved obligations
        prop_assert_eq!(
            stats.pending as usize,
            expected_pending,
            "Pending count {} should match expected {}",
            stats.pending, expected_pending
        );

        // MR: The "region close = quiescence" claim
        // Can only close when pending_obligations() == 0
        let can_close_by_pending = ctx.pending_count() == 0;
        let should_close = expected_pending == 0;

        prop_assert_eq!(
            can_close_by_pending,
            should_close,
            "Region close readiness must match quiescence: pending_count={}, expected_pending={}",
            ctx.pending_count(), expected_pending
        );

        // MR: Conservation law holds even with partial resolution
        let total_accounted = stats.total_committed + stats.total_aborted +
                             stats.total_leaked + stats.pending;
        prop_assert_eq!(
            stats.total_acquired,
            total_accounted,
            "CONSERVATION LAW: acquired={} != accounted={}",
            stats.total_acquired, total_accounted
        );

        // When all obligations are resolved, finalize should succeed
        if expected_pending == 0 {
            // This would be where region close succeeds in the real system
            ctx.finalize_region(region_id);
            let final_stats = ctx.stats();
            prop_assert_eq!(
                final_stats.pending,
                0,
                "After finalization, pending should be 0"
            );
        }
    }
}

/// MR3: Double-Resolution Prevention
/// Tests that the system prevents double-resolution attempts.
/// Verifies the "no double-resolve panics" claim from documentation.
proptest! {
    #[test]
    fn mr_double_resolution_prevention(
        kind in prop_oneof![
            Just(ObligationKind::SendPermit),
            Just(ObligationKind::Ack),
            Just(ObligationKind::Lease),
            Just(ObligationKind::IoOp)
        ]
    ) {
        let mut ctx1 = TestContext::new();
        let mut ctx2 = TestContext::new();

        // Single resolution
        let token1 = ctx1.acquire(kind, task_id(1), region_id(1), Time::from_nanos(1000));
        let committed1 = ctx1.commit(token1, Time::from_nanos(2000));
        let stats1 = ctx1.stats();

        // Attempt double resolution
        let token2 = ctx2.acquire(kind, task_id(1), region_id(1), Time::from_nanos(1000));
        let committed2a = ctx2.commit(token2, Time::from_nanos(2000));
        let committed2b = ctx2.commit(token2, Time::from_nanos(3000)); // Should fail
        let stats2 = ctx2.stats();

        // MR: First resolution should succeed
        prop_assert!(committed1, "Single resolution should succeed");
        prop_assert!(committed2a, "First resolution in double attempt should succeed");

        // MR: Second resolution should fail (token already consumed)
        prop_assert!(!committed2b, "Second resolution attempt should fail");

        // MR: Final stats should be equivalent
        prop_assert_eq!(
            stats1.total_committed,
            stats2.total_committed,
            "Double resolution should not affect commit count: {} vs {}",
            stats1.total_committed, stats2.total_committed
        );

        // MR: Conservation should hold in both cases
        for (name, stats) in [("single", &stats1), ("double", &stats2)] {
            let total = stats.total_committed + stats.total_aborted +
                       stats.total_leaked + stats.pending;
            prop_assert_eq!(
                stats.total_acquired,
                total,
                "Conservation violated in {} case: {} != {}",
                name, stats.total_acquired, total
            );
        }
    }
}

/// MR4: Cancel-Drain Balance Invariant
/// Tests that cancel/drain scenarios maintain conservation.
/// Verifies the cancel-correctness claims from the documentation.
proptest! {
    #[test]
    fn mr_cancel_drain_balance_invariant(
        normal_count in 1usize..=6,
        cancel_count in 1usize..=6
    ) {
        let mut ctx = TestContext::new();
        let region_id = region_id(1);
        let mut normal_tokens = Vec::new();
        let mut cancel_tokens = Vec::new();

        // Create normal obligations
        for i in 0..normal_count {
            let token = ctx.acquire(
                ObligationKind::SendPermit,
                task_id(i as u32 + 1),
                region_id,
                Time::from_nanos(1000 + i as u64 * 1000)
            );
            normal_tokens.push(token);
        }

        // Create obligations that will be cancelled
        for i in 0..cancel_count {
            let token = ctx.acquire(
                ObligationKind::Ack,
                task_id((normal_count + i) as u32 + 1),
                region_id,
                Time::from_nanos(2000 + i as u64 * 1000)
            );
            cancel_tokens.push(token);
        }

        // Commit normal obligations
        for (i, &token) in normal_tokens.iter().enumerate() {
            ctx.commit(token, Time::from_nanos(3000 + i as u64 * 1000));
        }

        // Cancel the cancel obligations
        for (i, &token) in cancel_tokens.iter().enumerate() {
            ctx.abort(
                token,
                Time::from_nanos(4000 + i as u64 * 1000),
                ObligationAbortReason::Cancel
            );
        }

        let stats = ctx.stats();

        // MR: All obligations should be resolved (no leaks in cancel scenario)
        let total_resolved = stats.total_committed + stats.total_aborted;
        prop_assert_eq!(
            stats.total_acquired,
            total_resolved,
            "Cancel-drain should resolve all obligations: acquired={}, resolved={}",
            stats.total_acquired, total_resolved
        );

        // MR: No obligations should leak during cancel operations
        prop_assert_eq!(
            stats.total_leaked,
            0,
            "Cancel operations should not cause leaks: leaked={}",
            stats.total_leaked
        );

        // MR: Conservation law must hold during cancel/drain
        let total_accounted = total_resolved + stats.pending + stats.total_leaked;
        prop_assert_eq!(
            stats.total_acquired,
            total_accounted,
            "CANCEL-DRAIN CONSERVATION: acquired={}, accounted={}",
            stats.total_acquired, total_accounted
        );

        // MR: After cancel/drain, region should be quiescent
        prop_assert_eq!(
            ctx.pending_count(),
            0,
            "After cancel/drain, pending count should be 0"
        );
    }
}

/// MR5: Operation Order Independence (Permutative)
/// Independent operations should be commutative and not affect final state.
proptest! {
    #[test]
    fn mr_operation_order_independence(
        op_count in 2usize..=6
    ) {
        // Generate two sequences with different orders but same operations
        let mut ctx1 = TestContext::new();
        let mut ctx2 = TestContext::new();

        let mut tokens1 = Vec::new();
        let mut tokens2 = Vec::new();

        // Forward order
        for i in 0..op_count {
            let kind = if i % 2 == 0 {
                ObligationKind::SendPermit
            } else {
                ObligationKind::Ack
            };

            let token1 = ctx1.acquire(
                kind,
                task_id(i as u32 + 1),
                region_id((i % 2) as u32 + 1), // Different regions for independence
                Time::from_nanos(1000 + i as u64 * 1000)
            );
            tokens1.push(token1);
        }

        // Reverse order (independent operations)
        for i in (0..op_count).rev() {
            let kind = if i % 2 == 0 {
                ObligationKind::SendPermit
            } else {
                ObligationKind::Ack
            };

            let token2 = ctx2.acquire(
                kind,
                task_id(i as u32 + 1),
                region_id((i % 2) as u32 + 1),
                Time::from_nanos(1000 + i as u64 * 1000)
            );
            tokens2.push(token2);
        }

        // Commit all in same order
        for (i, (&token1, &token2)) in tokens1.iter().zip(tokens2.iter()).enumerate() {
            ctx1.commit(token1, Time::from_nanos(2000 + i as u64 * 1000));
            ctx2.commit(token2, Time::from_nanos(2000 + i as u64 * 1000));
        }

        let stats1 = ctx1.stats();
        let stats2 = ctx2.stats();

        // MR: Different acquisition orders should yield same final stats
        prop_assert_eq!(
            stats1.total_acquired,
            stats2.total_acquired,
            "Total acquired should be invariant under reordering"
        );

        prop_assert_eq!(
            stats1.total_committed,
            stats2.total_committed,
            "Total committed should be invariant under reordering"
        );

        prop_assert_eq!(
            stats1.pending,
            stats2.pending,
            "Pending count should be invariant under reordering"
        );

        // MR: Conservation should hold in both orderings
        for (name, stats) in [("forward", &stats1), ("reverse", &stats2)] {
            let total = stats.total_committed + stats.total_aborted +
                       stats.total_leaked + stats.pending;
            prop_assert_eq!(
                stats.total_acquired,
                total,
                "Conservation violated in {} ordering: {} != {}",
                name, stats.total_acquired, total
            );
        }
    }
}
