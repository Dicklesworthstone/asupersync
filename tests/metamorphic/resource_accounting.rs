//! Metamorphic tests for observability::resource_accounting tracking invariants.
//!
//! These tests validate the core invariants of resource accounting using
//! metamorphic relations and property-based testing. The resource accounting
//! system tracks obligation lifecycles, budget consumption, admission control,
//! and high-water marks with atomic counters for deterministic behavior.
//!
//! ## Key Properties Tested
//!
//! 1. **Accounted resources sum correctly**: obligation lifecycle math is consistent
//! 2. **Release decrements counter**: committed/aborted/leaked obligations reduce pending
//! 3. **Peak usage monotonic**: high-water marks never decrease
//! 4. **Cancel returns resources**: cancelled operations don't leak accounting
//! 5. **Per-region isolation preserved**: accounting scoped to region boundaries
//!
//! ## Metamorphic Relations
//!
//! - **Conservation invariant**: reserved = committed + aborted + leaked + pending
//! - **Monotonic peaks**: peak(state₁) ≤ peak(state₂) for state₁ ⊆ state₂
//! - **Cancellation idempotence**: reserve+abort ≡ no-op for accounting balance
//! - **Isolation preservation**: operations on regionₐ don't affect regionᵦ accounting
//! - **Snapshot consistency**: derived pending ≡ global pending gauge

use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

use asupersync::observability::resource_accounting::{ResourceAccounting, ResourceAccountingSnapshot};
use asupersync::record::ObligationKind;
use asupersync::record::region::AdmissionKind;

// =============================================================================
// Test Data Generation
// =============================================================================

/// Generate obligation kinds for property testing.
fn obligation_kind() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
        Just(ObligationKind::SemaphorePermit),
    ]
}

/// Generate admission kinds for property testing.
fn admission_kind() -> impl Strategy<Value = AdmissionKind> {
    prop_oneof![
        Just(AdmissionKind::Child),
        Just(AdmissionKind::Task),
        Just(AdmissionKind::Obligation),
        Just(AdmissionKind::HeapBytes),
    ]
}

/// Generate obligation lifecycle operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObligationOp {
    Reserve(ObligationKind),
    Commit(ObligationKind),
    Abort(ObligationKind),
    Leak(ObligationKind),
}

impl ObligationOp {
    fn kind(&self) -> ObligationKind {
        match self {
            ObligationOp::Reserve(k) | ObligationOp::Commit(k) | ObligationOp::Abort(k) | ObligationOp::Leak(k) => *k,
        }
    }
}

/// Generate sequences of obligation operations.
fn obligation_operations() -> impl Strategy<Value = Vec<ObligationOp>> {
    prop::collection::vec(
        (obligation_kind(), prop_oneof![
            Just("reserve"),
            Just("commit"),
            Just("abort"),
            Just("leak"),
        ]).prop_map(|(kind, op)| {
            match op {
                "reserve" => ObligationOp::Reserve(kind),
                "commit" => ObligationOp::Commit(kind),
                "abort" => ObligationOp::Abort(kind),
                "leak" => ObligationOp::Leak(kind),
                _ => unreachable!(),
            }
        }),
        0..100,
    )
}

/// Generate budget consumption operations.
#[derive(Debug, Clone, Copy)]
enum BudgetOp {
    PollConsumed(u64),
    CostConsumed(u64),
    PollExhausted,
    CostExhausted,
    DeadlineMissed,
}

fn budget_operations() -> impl Strategy<Value = Vec<BudgetOp>> {
    prop::collection::vec(
        prop_oneof![
            (1u64..=1000).prop_map(BudgetOp::PollConsumed),
            (1u64..=10000).prop_map(BudgetOp::CostConsumed),
            Just(BudgetOp::PollExhausted),
            Just(BudgetOp::CostExhausted),
            Just(BudgetOp::DeadlineMissed),
        ],
        0..50,
    )
}

/// Generate admission control operations.
#[derive(Debug, Clone, Copy)]
enum AdmissionOp {
    Succeeded(AdmissionKind),
    Rejected(AdmissionKind),
}

fn admission_operations() -> impl Strategy<Value = Vec<AdmissionOp>> {
    prop::collection::vec(
        (admission_kind(), any::<bool>()).prop_map(|(kind, succeeded)| {
            if succeeded {
                AdmissionOp::Succeeded(kind)
            } else {
                AdmissionOp::Rejected(kind)
            }
        }),
        0..50,
    )
}

/// Generate high-water mark updates.
#[derive(Debug, Clone, Copy)]
enum HighWaterOp {
    UpdateTasks(i64),
    UpdateChildren(i64),
    UpdateHeapBytes(i64),
}

fn high_water_operations() -> impl Strategy<Value = Vec<HighWaterOp>> {
    prop::collection::vec(
        prop_oneof![
            (-100i64..=1000).prop_map(HighWaterOp::UpdateTasks),
            (-50i64..=500).prop_map(HighWaterOp::UpdateChildren),
            (0i64..=1000000).prop_map(HighWaterOp::UpdateHeapBytes),
        ],
        0..30,
    )
}

// =============================================================================
// Test Utilities
// =============================================================================

/// Apply obligation operations to accounting instance.
fn apply_obligation_ops(acc: &ResourceAccounting, ops: &[ObligationOp]) {
    for &op in ops {
        match op {
            ObligationOp::Reserve(kind) => acc.obligation_reserved(kind),
            ObligationOp::Commit(kind) => acc.obligation_committed(kind),
            ObligationOp::Abort(kind) => acc.obligation_aborted(kind),
            ObligationOp::Leak(kind) => acc.obligation_leaked(kind),
        }
    }
}

/// Apply budget operations to accounting instance.
fn apply_budget_ops(acc: &ResourceAccounting, ops: &[BudgetOp]) {
    for &op in ops {
        match op {
            BudgetOp::PollConsumed(amount) => acc.poll_consumed(amount),
            BudgetOp::CostConsumed(amount) => acc.cost_consumed(amount),
            BudgetOp::PollExhausted => acc.poll_quota_exhausted(),
            BudgetOp::CostExhausted => acc.cost_quota_exhausted(),
            BudgetOp::DeadlineMissed => acc.deadline_missed(),
        }
    }
}

/// Apply admission operations to accounting instance.
fn apply_admission_ops(acc: &ResourceAccounting, ops: &[AdmissionOp]) {
    for &op in ops {
        match op {
            AdmissionOp::Succeeded(kind) => acc.admission_succeeded(kind),
            AdmissionOp::Rejected(kind) => acc.admission_rejected(kind),
        }
    }
}

/// Apply high-water mark operations to accounting instance.
fn apply_high_water_ops(acc: &ResourceAccounting, ops: &[HighWaterOp]) {
    for &op in ops {
        match op {
            HighWaterOp::UpdateTasks(val) => acc.update_tasks_peak(val),
            HighWaterOp::UpdateChildren(val) => acc.update_children_peak(val),
            HighWaterOp::UpdateHeapBytes(val) => acc.update_heap_bytes_peak(val),
        }
    }
}

/// Count operations by type for validation.
fn count_obligation_ops(ops: &[ObligationOp]) -> HashMap<(ObligationKind, &'static str), usize> {
    let mut counts = HashMap::new();
    for &op in ops {
        let key = match op {
            ObligationOp::Reserve(kind) => (kind, "reserve"),
            ObligationOp::Commit(kind) => (kind, "commit"),
            ObligationOp::Abort(kind) => (kind, "abort"),
            ObligationOp::Leak(kind) => (kind, "leak"),
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

/// Calculate expected pending obligations from operation counts.
fn expected_pending_from_ops(ops: &[ObligationOp]) -> i64 {
    let counts = count_obligation_ops(ops);
    let all_kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
        ObligationKind::SemaphorePermit,
    ];

    let mut total_pending = 0i64;
    for kind in all_kinds {
        let reserved = counts.get(&(kind, "reserve")).copied().unwrap_or(0);
        let committed = counts.get(&(kind, "commit")).copied().unwrap_or(0);
        let aborted = counts.get(&(kind, "abort")).copied().unwrap_or(0);
        let leaked = counts.get(&(kind, "leak")).copied().unwrap_or(0);

        let kind_pending = (reserved as i64) - (committed as i64) - (aborted as i64) - (leaked as i64);
        total_pending += kind_pending.max(0); // Pending can't go negative per obligation kind
    }

    total_pending
}

// =============================================================================
// METAMORPHIC RELATION 1: Accounted Resources Sum Correctly
// =============================================================================

proptest! {
    /// MR1: The obligation lifecycle accounting must be mathematically consistent.
    ///
    /// For each obligation kind: reserved = committed + aborted + leaked + pending
    /// This is the fundamental conservation law of obligation accounting.
    #[test]
    fn mr1_accounted_resources_sum_correctly(ops in obligation_operations()) {
        let acc = ResourceAccounting::new();
        apply_obligation_ops(&acc, &ops);

        let snapshot = acc.snapshot();
        let counts = count_obligation_ops(&ops);

        // Test conservation law for each obligation kind
        for &kind in &[ObligationKind::SendPermit, ObligationKind::Ack,
                       ObligationKind::Lease, ObligationKind::IoOp, ObligationKind::SemaphorePermit] {
            let reserved = counts.get(&(kind, "reserve")).copied().unwrap_or(0) as u64;
            let committed = counts.get(&(kind, "commit")).copied().unwrap_or(0) as u64;
            let aborted = counts.get(&(kind, "abort")).copied().unwrap_or(0) as u64;
            let leaked = counts.get(&(kind, "leak")).copied().unwrap_or(0) as u64;

            let kind_stats = snapshot.obligation_stats.iter()
                .find(|s| s.kind == kind)
                .expect("kind stats must be present");

            // MR1 ASSERTION: Conservation law holds
            prop_assert_eq!(
                kind_stats.reserved,
                reserved,
                "MR1 VIOLATION: reserved count mismatch for {:?}", kind
            );

            prop_assert_eq!(
                kind_stats.committed,
                committed,
                "MR1 VIOLATION: committed count mismatch for {:?}", kind
            );

            prop_assert_eq!(
                kind_stats.aborted,
                aborted,
                "MR1 VIOLATION: aborted count mismatch for {:?}", kind
            );

            prop_assert_eq!(
                kind_stats.leaked,
                leaked,
                "MR1 VIOLATION: leaked count mismatch for {:?}", kind
            );

            // The fundamental conservation equation
            let accounted_total = kind_stats.committed + kind_stats.aborted + kind_stats.leaked + kind_stats.pending();
            prop_assert_eq!(
                kind_stats.reserved,
                accounted_total,
                "MR1 VIOLATION: Conservation law broken for {:?}: reserved={} != committed={} + aborted={} + leaked={} + pending={}",
                kind, kind_stats.reserved, kind_stats.committed, kind_stats.aborted, kind_stats.leaked, kind_stats.pending()
            );
        }

        // MR1 ASSERTION: Global accounting consistency
        let total_reserved = snapshot.total_reserved();
        let total_accounted = snapshot.total_committed() + snapshot.total_aborted() +
                             snapshot.total_leaked() + snapshot.total_pending_by_stats();

        prop_assert_eq!(
            total_reserved,
            total_accounted,
            "MR1 VIOLATION: Global conservation law broken: {} != {}",
            total_reserved, total_accounted
        );
    }
}

// =============================================================================
// METAMORPHIC RELATION 2: Release Decrements Counter
// =============================================================================

proptest! {
    /// MR2: Every commit/abort/leak operation must correctly decrement pending count.
    ///
    /// The pending gauge tracks live obligations and must decrease when obligations
    /// are resolved via commit, abort, or leak operations.
    #[test]
    fn mr2_release_decrements_counter(
        reserve_ops in prop::collection::vec(obligation_kind(), 1..20),
        resolution_ops in prop::collection::vec(obligation_kind(), 1..20)
    ) {
        let acc = ResourceAccounting::new();

        // First, reserve some obligations
        for &kind in &reserve_ops {
            acc.obligation_reserved(kind);
        }

        let pending_after_reserves = acc.obligations_pending();
        prop_assert_eq!(pending_after_reserves, reserve_ops.len() as i64);

        // Then resolve some obligations
        let mut expected_pending = pending_after_reserves;
        for &kind in &resolution_ops {
            let pending_before = acc.obligations_pending();

            // Test commit decrements
            acc.obligation_committed(kind);
            let pending_after_commit = acc.obligations_pending();

            // MR2 ASSERTION: Commit decrements pending (or stays at zero)
            prop_assert!(
                pending_after_commit <= pending_before,
                "MR2 VIOLATION: Commit did not decrement pending: {} -> {}",
                pending_before, pending_after_commit
            );

            if pending_before > 0 {
                prop_assert_eq!(
                    pending_after_commit,
                    pending_before - 1,
                    "MR2 VIOLATION: Commit should decrement by 1: {} -> {}",
                    pending_before, pending_after_commit
                );
                expected_pending -= 1;
            }
        }

        // Test abort and leak operations similarly
        for &kind in &resolution_ops {
            let pending_before = acc.obligations_pending();
            acc.obligation_aborted(kind);
            let pending_after_abort = acc.obligations_pending();

            // MR2 ASSERTION: Abort decrements pending
            prop_assert!(
                pending_after_abort <= pending_before,
                "MR2 VIOLATION: Abort did not decrement pending: {} -> {}",
                pending_before, pending_after_abort
            );
        }

        // MR2 ASSERTION: Pending never goes negative
        prop_assert!(
            acc.obligations_pending() >= 0,
            "MR2 VIOLATION: Pending obligations went negative: {}",
            acc.obligations_pending()
        );
    }
}

// =============================================================================
// METAMORPHIC RELATION 3: Peak Usage Monotonic
// =============================================================================

proptest! {
    /// MR3: Peak usage counters must be monotonically non-decreasing.
    ///
    /// High-water marks capture the maximum value ever seen and should never decrease.
    /// This applies to obligation peaks, task peaks, children peaks, and heap peaks.
    #[test]
    fn mr3_peak_usage_monotonic(
        obligation_ops in obligation_operations(),
        high_water_ops in high_water_operations()
    ) {
        let acc = ResourceAccounting::new();

        let mut max_obligations_seen = 0i64;
        let mut max_tasks_seen = 0i64;
        let mut max_children_seen = 0i64;
        let mut max_heap_bytes_seen = 0i64;

        // Apply operations and track expected peaks
        for &op in &obligation_ops {
            match op {
                ObligationOp::Reserve(_) => {
                    acc.obligation_reserved(op.kind());
                    let current_pending = acc.obligations_pending();
                    max_obligations_seen = max_obligations_seen.max(current_pending);

                    // MR3 ASSERTION: Obligation peak is monotonic
                    let current_peak = acc.obligations_peak();
                    prop_assert!(
                        current_peak >= max_obligations_seen,
                        "MR3 VIOLATION: Obligation peak decreased: expected >= {}, got {}",
                        max_obligations_seen, current_peak
                    );
                }
                _ => {
                    apply_obligation_ops(&acc, &[op]);
                }
            }

            // MR3 ASSERTION: Peak never decreases between operations
            let current_peak = acc.obligations_peak();
            prop_assert!(
                current_peak >= max_obligations_seen,
                "MR3 VIOLATION: Obligation peak decreased during operation {:?}", op
            );
        }

        // Test high-water mark monotonicity
        for &op in &high_water_ops {
            match op {
                HighWaterOp::UpdateTasks(val) => {
                    acc.update_tasks_peak(val);
                    max_tasks_seen = max_tasks_seen.max(val);

                    // MR3 ASSERTION: Tasks peak is monotonic
                    let current_peak = acc.tasks_peak();
                    prop_assert!(
                        current_peak >= max_tasks_seen,
                        "MR3 VIOLATION: Tasks peak decreased: expected >= {}, got {}",
                        max_tasks_seen, current_peak
                    );
                }
                HighWaterOp::UpdateChildren(val) => {
                    acc.update_children_peak(val);
                    max_children_seen = max_children_seen.max(val);

                    // MR3 ASSERTION: Children peak is monotonic
                    let current_peak = acc.children_peak();
                    prop_assert!(
                        current_peak >= max_children_seen,
                        "MR3 VIOLATION: Children peak decreased: expected >= {}, got {}",
                        max_children_seen, current_peak
                    );
                }
                HighWaterOp::UpdateHeapBytes(val) => {
                    acc.update_heap_bytes_peak(val);
                    max_heap_bytes_seen = max_heap_bytes_seen.max(val);

                    // MR3 ASSERTION: Heap bytes peak is monotonic
                    let current_peak = acc.heap_bytes_peak();
                    prop_assert!(
                        current_peak >= max_heap_bytes_seen,
                        "MR3 VIOLATION: Heap bytes peak decreased: expected >= {}, got {}",
                        max_heap_bytes_seen, current_peak
                    );
                }
            }
        }

        // Final consistency check
        let snapshot = acc.snapshot();
        prop_assert!(
            snapshot.obligations_peak >= max_obligations_seen,
            "MR3 VIOLATION: Final obligation peak inconsistent"
        );
        prop_assert!(
            snapshot.tasks_peak >= max_tasks_seen,
            "MR3 VIOLATION: Final tasks peak inconsistent"
        );
        prop_assert!(
            snapshot.children_peak >= max_children_seen,
            "MR3 VIOLATION: Final children peak inconsistent"
        );
        prop_assert!(
            snapshot.heap_bytes_peak >= max_heap_bytes_seen,
            "MR3 VIOLATION: Final heap bytes peak inconsistent"
        );
    }
}

// =============================================================================
// METAMORPHIC RELATION 4: Cancel Returns Resources
// =============================================================================

proptest! {
    /// MR4: Cancelled operations must properly return accounted resources.
    ///
    /// When obligations are aborted (cancelled), they must be properly accounted
    /// for and not leak resources. The cancellation should be equivalent to
    /// never having reserved the obligation in the first place.
    #[test]
    fn mr4_cancel_returns_resources(
        kinds in prop::collection::vec(obligation_kind(), 1..10)
    ) {
        let acc1 = ResourceAccounting::new();
        let acc2 = ResourceAccounting::new();

        // Scenario 1: Reserve then immediately abort (cancel)
        for &kind in &kinds {
            acc1.obligation_reserved(kind);
            acc1.obligation_aborted(kind);
        }

        // Scenario 2: Never reserve (no-op)
        // acc2 stays empty

        let snapshot1 = acc1.snapshot();
        let snapshot2 = acc2.snapshot();

        // MR4 ASSERTION: Reserve + abort should be equivalent to no-op
        prop_assert_eq!(
            snapshot1.obligations_pending,
            snapshot2.obligations_pending,
            "MR4 VIOLATION: Cancel didn't return pending count to baseline"
        );

        // MR4 ASSERTION: But the accounting ledger should reflect the operations
        let total_reserved1 = snapshot1.total_reserved();
        let total_aborted1 = snapshot1.total_aborted();
        let total_reserved2 = snapshot2.total_reserved();

        prop_assert_eq!(
            total_reserved1,
            kinds.len() as u64,
            "MR4 VIOLATION: Reserved count not tracked properly"
        );
        prop_assert_eq!(
            total_aborted1,
            kinds.len() as u64,
            "MR4 VIOLATION: Aborted count not tracked properly"
        );
        prop_assert_eq!(
            total_reserved2,
            0,
            "MR4 VIOLATION: Baseline should have no reserves"
        );

        // Test reserve + abort idempotence
        let acc3 = ResourceAccounting::new();

        // Apply reserve+abort pairs multiple times
        for _ in 0..3 {
            for &kind in &kinds {
                acc3.obligation_reserved(kind);
                acc3.obligation_aborted(kind);
            }
        }

        let snapshot3 = acc3.snapshot();

        // MR4 ASSERTION: Multiple reserve+abort cycles don't accumulate pending
        prop_assert_eq!(
            snapshot3.obligations_pending,
            0,
            "MR4 VIOLATION: Multiple cancel cycles accumulated pending obligations"
        );

        // But the ledger should reflect all operations
        prop_assert_eq!(
            snapshot3.total_reserved(),
            (kinds.len() * 3) as u64,
            "MR4 VIOLATION: Multiple reserves not counted"
        );
        prop_assert_eq!(
            snapshot3.total_aborted(),
            (kinds.len() * 3) as u64,
            "MR4 VIOLATION: Multiple aborts not counted"
        );
    }
}

// =============================================================================
// METAMORPHIC RELATION 5: Per-Region Isolation Preserved
// =============================================================================

proptest! {
    /// MR5: Resource accounting should maintain isolation boundaries.
    ///
    /// Operations on different ResourceAccounting instances should be completely
    /// independent. This tests that there are no global variables or shared state
    /// that could cause cross-contamination between regions.
    #[test]
    fn mr5_per_region_isolation_preserved(
        ops_region_a in obligation_operations(),
        ops_region_b in obligation_operations(),
        budget_ops_a in budget_operations(),
        budget_ops_b in budget_operations(),
        admission_ops_a in admission_operations(),
        admission_ops_b in admission_operations()
    ) {
        // Create two independent accounting instances (simulating different regions)
        let acc_a = ResourceAccounting::new();
        let acc_b = ResourceAccounting::new();

        // Apply operations to region A
        apply_obligation_ops(&acc_a, &ops_region_a);
        apply_budget_ops(&acc_a, &budget_ops_a);
        apply_admission_ops(&acc_a, &admission_ops_a);

        // Take snapshot of region B before any operations on B
        let snapshot_b_before = acc_b.snapshot();

        // Apply operations to region B
        apply_obligation_ops(&acc_b, &ops_region_b);
        apply_budget_ops(&acc_b, &budget_ops_b);
        apply_admission_ops(&acc_b, &admission_ops_b);

        let snapshot_a = acc_a.snapshot();
        let snapshot_b_after = acc_b.snapshot();

        // MR5 ASSERTION: Region A operations don't affect region B baseline
        prop_assert_eq!(
            snapshot_b_before.total_reserved(),
            0,
            "MR5 VIOLATION: Region B contaminated before its own operations"
        );
        prop_assert_eq!(
            snapshot_b_before.obligations_pending,
            0,
            "MR5 VIOLATION: Region B pending contaminated"
        );
        prop_assert_eq!(
            snapshot_b_before.poll_quota_consumed,
            0,
            "MR5 VIOLATION: Region B budget contaminated"
        );
        prop_assert_eq!(
            snapshot_b_before.total_rejections(),
            0,
            "MR5 VIOLATION: Region B admissions contaminated"
        );

        // MR5 ASSERTION: Create a fresh region C and verify it matches original state
        let acc_c = ResourceAccounting::new();
        let snapshot_c = acc_c.snapshot();

        prop_assert_eq!(
            snapshot_c.total_reserved(),
            snapshot_b_before.total_reserved(),
            "MR5 VIOLATION: Fresh region doesn't match baseline"
        );
        prop_assert_eq!(
            snapshot_c.obligations_pending,
            snapshot_b_before.obligations_pending,
            "MR5 VIOLATION: Fresh region pending contaminated"
        );

        // MR5 ASSERTION: Verify each region's accounting is independent
        let counts_a = count_obligation_ops(&ops_region_a);
        let counts_b = count_obligation_ops(&ops_region_b);

        // Region A should only reflect its own operations
        let expected_a_total = counts_a.values().sum::<usize>() as u64;
        let actual_a_total = snapshot_a.total_reserved() + snapshot_a.total_committed() +
                            snapshot_a.total_aborted() + snapshot_a.total_leaked();
        prop_assert_eq!(
            actual_a_total,
            expected_a_total,
            "MR5 VIOLATION: Region A accounting doesn't match its operations"
        );

        // Region B should only reflect its own operations
        let expected_b_total = counts_b.values().sum::<usize>() as u64;
        let actual_b_total = snapshot_b_after.total_reserved() + snapshot_b_after.total_committed() +
                            snapshot_b_after.total_aborted() + snapshot_b_after.total_leaked();
        prop_assert_eq!(
            actual_b_total,
            expected_b_total,
            "MR5 VIOLATION: Region B accounting doesn't match its operations"
        );

        // Test concurrent-like access (sequential but interleaved)
        let acc_d = ResourceAccounting::new();
        let acc_e = ResourceAccounting::new();

        // Interleave operations on both regions
        let max_len = ops_region_a.len().max(ops_region_b.len());
        for i in 0..max_len {
            if i < ops_region_a.len() {
                apply_obligation_ops(&acc_d, &ops_region_a[i..i+1]);
            }
            if i < ops_region_b.len() {
                apply_obligation_ops(&acc_e, &ops_region_b[i..i+1]);
            }
        }

        let snapshot_d = acc_d.snapshot();
        let snapshot_e = acc_e.snapshot();

        // MR5 ASSERTION: Interleaved operations produce same results as batched
        prop_assert_eq!(
            snapshot_d.total_reserved(),
            snapshot_a.total_reserved(),
            "MR5 VIOLATION: Interleaved operations broke isolation for region D"
        );
        prop_assert_eq!(
            snapshot_e.total_reserved(),
            snapshot_b_after.total_reserved(),
            "MR5 VIOLATION: Interleaved operations broke isolation for region E"
        );
    }
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn comprehensive_accounting_workflow() {
        let acc = ResourceAccounting::new();

        // Simulate a realistic obligation lifecycle
        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::Lease);

        assert_eq!(acc.obligations_pending(), 3);
        assert_eq!(acc.obligations_peak(), 3);

        acc.obligation_committed(ObligationKind::SendPermit);
        assert_eq!(acc.obligations_pending(), 2);

        acc.obligation_aborted(ObligationKind::SendPermit);
        assert_eq!(acc.obligations_pending(), 1);

        acc.obligation_leaked(ObligationKind::Lease);
        assert_eq!(acc.obligations_pending(), 0);

        // Peak should remain at 3
        assert_eq!(acc.obligations_peak(), 3);

        let snapshot = acc.snapshot();
        assert_eq!(snapshot.total_reserved(), 3);
        assert_eq!(snapshot.total_committed(), 1);
        assert_eq!(snapshot.total_aborted(), 1);
        assert_eq!(snapshot.total_leaked(), 1);
        assert!(!snapshot.is_leak_free());
        assert!(!snapshot.has_unresolved_obligations());
    }

    #[test]
    fn budget_and_admission_tracking() {
        let acc = ResourceAccounting::new();

        // Budget consumption
        acc.poll_consumed(100);
        acc.cost_consumed(500);
        acc.poll_quota_exhausted();
        acc.deadline_missed();

        // Admission control
        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_rejected(AdmissionKind::Task);
        acc.admission_rejected(AdmissionKind::Child);

        let snapshot = acc.snapshot();
        assert_eq!(snapshot.poll_quota_consumed, 100);
        assert_eq!(snapshot.cost_quota_consumed, 500);
        assert_eq!(snapshot.poll_quota_exhaustions, 1);
        assert_eq!(snapshot.deadline_misses, 1);
        assert_eq!(snapshot.total_rejections(), 2);

        // Test admission stats per kind
        let task_stats = snapshot.admission_stats.iter()
            .find(|s| s.kind == AdmissionKind::Task)
            .unwrap();
        assert_eq!(task_stats.successes, 2);
        assert_eq!(task_stats.rejections, 1);
        assert!((task_stats.rejection_rate() - 1.0/3.0).abs() < 0.001);
    }

    #[test]
    fn high_water_marks_monotonicity() {
        let acc = ResourceAccounting::new();

        acc.update_tasks_peak(10);
        assert_eq!(acc.tasks_peak(), 10);

        acc.update_tasks_peak(5); // Should not decrease
        assert_eq!(acc.tasks_peak(), 10);

        acc.update_tasks_peak(15); // Should increase
        assert_eq!(acc.tasks_peak(), 15);

        acc.update_children_peak(100);
        acc.update_heap_bytes_peak(1024);

        let snapshot = acc.snapshot();
        assert_eq!(snapshot.tasks_peak, 15);
        assert_eq!(snapshot.children_peak, 100);
        assert_eq!(snapshot.heap_bytes_peak, 1024);
    }

    #[test]
    fn snapshot_derived_vs_global_pending() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::Ack);

        let snapshot = acc.snapshot();

        // Should be consistent when operations are correct
        assert!(!snapshot.has_accounting_mismatch());
        assert_eq!(snapshot.obligations_pending as u64, snapshot.total_pending_by_stats());
    }

    #[test]
    fn accounting_isolation_between_instances() {
        let acc1 = ResourceAccounting::new();
        let acc2 = ResourceAccounting::new();

        acc1.obligation_reserved(ObligationKind::SendPermit);
        acc1.poll_consumed(100);
        acc1.admission_rejected(AdmissionKind::Task);

        // acc2 should be unaffected
        assert_eq!(acc2.obligations_pending(), 0);
        assert_eq!(acc2.total_poll_consumed(), 0);
        assert_eq!(acc2.admissions_rejected_total(), 0);

        acc2.obligation_reserved(ObligationKind::Lease);

        // acc1 should be unaffected by acc2 operations
        assert_eq!(acc1.obligations_reserved_by_kind(ObligationKind::Lease), 0);
        assert_eq!(acc1.obligations_reserved_by_kind(ObligationKind::SendPermit), 1);
    }
}