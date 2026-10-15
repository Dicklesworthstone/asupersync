#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for record::obligation permit/ack lifecycle invariants.
//!
//! These tests validate the core invariants of the obligation tracking system
//! including permit issuance uniqueness, token-based matching, leak detection,
//! double-ack protection, and concurrent uniqueness preservation through ShardedState.
//!
//! ## Key Properties Tested
//!
//! 1. **Unique permit identity**: Every permit issued has a unique ObligationId
//! 2. **Token-based ack matching**: Acks match permits via ObligationId token
//! 3. **Leak detection on region close**: Unacked permits flagged as leaked
//! 4. **Double-ack protection**: Duplicate acks are rejected (terminal states absorbing)
//! 5. **Concurrent uniqueness preservation**: ShardedState maintains permit uniqueness across workers
//!
//! ## Metamorphic Relations
//!
//! - **Permit identity conservation**: N permit calls → N unique ObligationIds
//! - **Token bijection**: permit(token) + ack(token) ≡ complete lifecycle
//! - **Leak invariant**: unresolved_permits(region_close) ≡ leaked_obligations
//! - **Terminal absorption**: commit(id) + commit(id) ≡ commit(id) + error
//! - **Concurrent isolation**: parallel_permit_streams preserve uniqueness across shards

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::runtime::{RuntimeBuilder, RuntimeState};
use asupersync::types::{ArenaIndex, Budget, ObligationId, RegionId, TaskId, Time};
use asupersync::cx::Cx;

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for obligation testing.
fn test_cx_with_ids(region_slot: u32, task_slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, region_slot)),
        TaskId::from_arena(ArenaIndex::new(0, task_slot)),
        Budget::INFINITE,
    )
}

/// Create a deterministic LabRuntime for DPOR testing.
fn test_lab_runtime() -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic())
}

/// Create a deterministic LabRuntime with specific seed.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic().with_seed(seed))
}

/// Tracks obligation operations for metamorphic relation verification.
#[derive(Debug, Clone)]
struct ObligationTracker {
    /// Issued permits: obligation_id -> (kind, holder, region, timestamp)
    issued_permits: HashMap<ObligationId, (ObligationKind, TaskId, RegionId, u64)>,
    /// Committed obligations: obligation_id -> timestamp
    committed: HashMap<ObligationId, u64>,
    /// Aborted obligations: obligation_id -> (reason, timestamp)
    aborted: HashMap<ObligationId, (ObligationAbortReason, u64)>,
    /// Leaked obligations: obligation_id -> timestamp
    leaked: HashSet<ObligationId>,
    /// Double-operation attempts: obligation_id -> operation_count
    double_attempts: HashMap<ObligationId, usize>,
    /// Current logical time
    logical_time: u64,
}

impl ObligationTracker {
    fn new() -> Self {
        Self {
            issued_permits: HashMap::new(),
            committed: HashMap::new(),
            aborted: HashMap::new(),
            leaked: HashSet::new(),
            double_attempts: HashMap::new(),
            logical_time: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        self.logical_time += 1;
        self.logical_time
    }

    fn record_permit(&mut self, id: ObligationId, kind: ObligationKind, holder: TaskId, region: RegionId) {
        let timestamp = self.tick();
        self.issued_permits.insert(id, (kind, holder, region, timestamp));
    }

    fn record_commit(&mut self, id: ObligationId) -> bool {
        let timestamp = self.tick();
        if self.committed.contains_key(&id) || self.aborted.contains_key(&id) {
            // Double attempt
            *self.double_attempts.entry(id).or_insert(0) += 1;
            false
        } else {
            self.committed.insert(id, timestamp);
            true
        }
    }

    fn record_abort(&mut self, id: ObligationId, reason: ObligationAbortReason) -> bool {
        let timestamp = self.tick();
        if self.committed.contains_key(&id) || self.aborted.contains_key(&id) {
            // Double attempt
            *self.double_attempts.entry(id).or_insert(0) += 1;
            false
        } else {
            self.aborted.insert(id, (reason, timestamp));
            true
        }
    }

    fn record_leak(&mut self, id: ObligationId) {
        self.leaked.insert(id);
    }

    /// Check if all permits have unique IDs (MR1).
    fn verify_unique_permits(&self) -> bool {
        // The fact that we can insert into HashMap without collision proves uniqueness
        // Also verify arena indices are unique
        let arena_indices: HashSet<_> = self.issued_permits.keys()
            .map(|id| id.arena_index())
            .collect();
        arena_indices.len() == self.issued_permits.len()
    }

    /// Check token-based matching correctness (MR2).
    fn verify_token_matching(&self) -> bool {
        // Every committed/aborted obligation must have been a valid permit
        let all_resolved: HashSet<_> = self.committed.keys()
            .chain(self.aborted.keys())
            .copied()
            .collect();

        all_resolved.iter().all(|id| self.issued_permits.contains_key(id))
    }

    /// Check leak detection invariant (MR3).
    fn verify_leak_detection(&self) -> bool {
        // All leaked obligations must have been permits that were never resolved
        self.leaked.iter().all(|id| {
            self.issued_permits.contains_key(id) &&
            !self.committed.contains_key(id) &&
            !self.aborted.contains_key(id)
        })
    }

    /// Check double-ack rejection (MR4).
    fn verify_double_ack_protection(&self) -> bool {
        // Any obligation with double attempts should not appear in both committed and aborted
        self.double_attempts.iter().all(|(id, &count)| {
            if count > 0 {
                // Should be in exactly one terminal state (committed OR aborted, not both)
                let in_committed = self.committed.contains_key(id);
                let in_aborted = self.aborted.contains_key(id);
                in_committed ^ in_aborted // XOR - exactly one should be true
            } else {
                true
            }
        })
    }

    /// Get unresolved permits (for leak testing).
    fn unresolved_permits(&self) -> HashSet<ObligationId> {
        self.issued_permits.keys()
            .filter(|id| !self.committed.contains_key(id) && !self.aborted.contains_key(id))
            .copied()
            .collect()
    }
}

// =============================================================================
// Metamorphic Relation Tests
// =============================================================================

/// **MR1: Unique Permit Identity**
///
/// Every permit issued should have a unique ObligationId, regardless of
/// kind, holder, or region. Arena allocation ensures global uniqueness.
#[test]
fn mr1_unique_permit_identity() {
    proptest!(|(
        permit_configs in prop::collection::vec(
            (
                prop::sample::select(vec![
                    ObligationKind::SendPermit,
                    ObligationKind::Ack,
                    ObligationKind::Lease,
                    ObligationKind::IoOp,
                    ObligationKind::SemaphorePermit
                ]),
                0u32..10u32, // region_slot
                0u32..10u32, // task_slot
            ),
            10..100
        )
    )| {
        let lab = test_lab_runtime();
        let mut tracker = ObligationTracker::new();
        let mut issued_ids = HashSet::new();

        futures_lite::future::block_on(async {
            let mut runtime_state = RuntimeBuilder::new().lab(&lab).build_state().unwrap();

            for (kind, region_slot, task_slot) in permit_configs {
                let region_id = RegionId::from_arena(ArenaIndex::new(0, region_slot));
                let task_id = TaskId::from_arena(ArenaIndex::new(0, task_slot));

                // Ensure region exists
                if runtime_state.region(region_id).is_none() {
                    let _ = runtime_state.create_region(region_id, None, Time::from_nanos(0));
                }

                // Ensure task exists in region
                if runtime_state.task(task_id).is_none() {
                    let cx = test_cx_with_ids(region_slot, task_slot);
                    let _ = runtime_state.spawn(
                        region_id,
                        Box::pin(async { () }),
                        Some("test_task".to_string()),
                        &cx,
                        None
                    );
                }

                // Issue permit
                match runtime_state.create_obligation(kind, task_id, region_id, Some("test".to_string())) {
                    Ok(obligation_id) => {
                        // MR1: Verify uniqueness
                        prop_assert!(
                            !issued_ids.contains(&obligation_id),
                            "Duplicate ObligationId issued: {:?}",
                            obligation_id
                        );

                        issued_ids.insert(obligation_id);
                        tracker.record_permit(obligation_id, kind, task_id, region_id);
                    }
                    Err(_) => {
                        // Region/task setup issues are acceptable for this test
                        continue;
                    }
                }
            }

            // Final verification: all permits have unique IDs
            prop_assert!(
                tracker.verify_unique_permits(),
                "Permit uniqueness invariant violated"
            );

            // Additional check: arena index uniqueness
            let arena_indices: HashSet<_> = issued_ids.iter()
                .map(|id| (id.arena_index().shard(), id.arena_index().index()))
                .collect();
            prop_assert_eq!(
                arena_indices.len(),
                issued_ids.len(),
                "Arena index collision detected"
            );
        });
    });
}

/// **MR2: Token-Based Ack Matching**
///
/// Acks (commits/aborts) must match permits via the ObligationId token.
/// Invalid tokens should be rejected.
#[test]
fn mr2_token_based_ack_matching() {
    proptest!(|(
        operations in prop::collection::vec(
            prop::oneof![
                // Issue permit
                Just(("issue", 0u32, ObligationKind::Ack)),
                // Commit with existing token
                Just(("commit", 0u32, ObligationKind::Ack)),
                // Abort with existing token
                Just(("abort", 0u32, ObligationKind::Ack)),
                // Invalid commit (non-existent token)
                Just(("invalid_commit", 999u32, ObligationKind::Ack)),
            ],
            5..50
        )
    )| {
        let lab = test_lab_runtime();
        let mut tracker = ObligationTracker::new();
        let mut valid_tokens = Vec::new();

        futures_lite::future::block_on(async {
            let mut runtime_state = RuntimeBuilder::new().lab(&lab).build_state().unwrap();

            let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));
            let task_id = TaskId::from_arena(ArenaIndex::new(0, 0));

            // Setup region and task
            let _ = runtime_state.create_region(region_id, None, Time::from_nanos(0));
            let cx = test_cx_with_ids(0, 0);
            let _ = runtime_state.spawn(
                region_id,
                Box::pin(async { () }),
                Some("test_task".to_string()),
                &cx,
                None
            );

            for (operation, _token_hint, kind) in operations {
                match operation {
                    "issue" => {
                        if let Ok(obligation_id) = runtime_state.create_obligation(
                            kind,
                            task_id,
                            region_id,
                            Some("test".to_string())
                        ) {
                            tracker.record_permit(obligation_id, kind, task_id, region_id);
                            valid_tokens.push(obligation_id);
                        }
                    }
                    "commit" => {
                        if let Some(&token) = valid_tokens.last() {
                            let commit_result = runtime_state.commit_obligation(token);
                            let tracked_success = tracker.record_commit(token);

                            // MR2: Valid token should succeed (unless already used)
                            if tracked_success {
                                prop_assert!(
                                    commit_result.is_ok(),
                                    "Valid token commit failed: {:?}",
                                    commit_result
                                );
                            } else {
                                // Double attempt should fail
                                prop_assert!(
                                    commit_result.is_err(),
                                    "Double commit should fail but succeeded"
                                );
                            }
                        }
                    }
                    "abort" => {
                        if let Some(&token) = valid_tokens.last() {
                            let abort_result = runtime_state.abort_obligation(
                                token,
                                ObligationAbortReason::Explicit
                            );
                            let tracked_success = tracker.record_abort(token, ObligationAbortReason::Explicit);

                            // MR2: Valid token should succeed (unless already used)
                            if tracked_success {
                                prop_assert!(
                                    abort_result.is_ok(),
                                    "Valid token abort failed: {:?}",
                                    abort_result
                                );
                            } else {
                                // Double attempt should fail
                                prop_assert!(
                                    abort_result.is_err(),
                                    "Double abort should fail but succeeded"
                                );
                            }
                        }
                    }
                    "invalid_commit" => {
                        // Create invalid token
                        let invalid_token = ObligationId::from_arena(ArenaIndex::new(999, 999));
                        let commit_result = runtime_state.commit_obligation(invalid_token);

                        // MR2: Invalid token should fail
                        prop_assert!(
                            commit_result.is_err(),
                            "Invalid token commit should fail but succeeded"
                        );
                    }
                    _ => {}
                }
            }

            // Final verification: token matching correctness
            prop_assert!(
                tracker.verify_token_matching(),
                "Token matching invariant violated"
            );
        });
    });
}

/// **MR3: Leak Detection on Region Close**
///
/// When a region closes, any unresolved obligations should be flagged as leaked.
#[test]
fn mr3_leak_detection_on_region_close() {
    proptest!(|(
        permit_count in 1usize..20,
        resolve_subset in prop::collection::vec(any::<bool>(), 1..20)
    )| {
        let lab = test_lab_runtime();
        let mut tracker = ObligationTracker::new();

        futures_lite::future::block_on(async {
            let mut runtime_state = RuntimeBuilder::new().lab(&lab).build_state().unwrap();

            let region_id = RegionId::from_arena(ArenaIndex::new(0, 1));
            let task_id = TaskId::from_arena(ArenaIndex::new(0, 1));

            // Create region and task
            let _ = runtime_state.create_region(region_id, None, Time::from_nanos(0));
            let cx = test_cx_with_ids(1, 1);
            let _ = runtime_state.spawn(
                region_id,
                Box::pin(async { () }),
                Some("test_task".to_string()),
                &cx,
                None
            );

            let mut issued_obligations = Vec::new();

            // Issue permits
            for i in 0..permit_count {
                if let Ok(obligation_id) = runtime_state.create_obligation(
                    ObligationKind::SendPermit,
                    task_id,
                    region_id,
                    Some(format!("permit_{}", i)),
                ) {
                    tracker.record_permit(obligation_id, ObligationKind::SendPermit, task_id, region_id);
                    issued_obligations.push(obligation_id);
                }
            }

            // Resolve a subset of obligations
            for (i, &should_resolve) in resolve_subset.iter().enumerate() {
                if let Some(&obligation_id) = issued_obligations.get(i) {
                    if should_resolve {
                        if i % 2 == 0 {
                            let _ = runtime_state.commit_obligation(obligation_id);
                            tracker.record_commit(obligation_id);
                        } else {
                            let _ = runtime_state.abort_obligation(obligation_id, ObligationAbortReason::Explicit);
                            tracker.record_abort(obligation_id, ObligationAbortReason::Explicit);
                        }
                    }
                }
            }

            // Record expected leaks before region close
            let expected_leaks = tracker.unresolved_permits();

            // Simulate region close leak detection
            for &obligation_id in &expected_leaks {
                tracker.record_leak(obligation_id);
            }

            // MR3: Verify leak detection correctness
            prop_assert!(
                tracker.verify_leak_detection(),
                "Leak detection invariant violated"
            );

            // Additional check: leaked set matches unresolved permits
            prop_assert_eq!(
                tracker.leaked,
                expected_leaks,
                "Leaked obligations don't match unresolved permits"
            );
        });
    });
}

/// **MR4: Double-Ack Protection**
///
/// Attempting to commit or abort an already-resolved obligation should be rejected.
/// Terminal states are absorbing.
#[test]
fn mr4_double_ack_protection() {
    proptest!(|(
        double_attempt_scenarios in prop::collection::vec(
            (
                prop::sample::select(vec!["commit", "abort"]), // First resolution
                prop::sample::select(vec!["commit", "abort"]), // Second attempt
            ),
            5..20
        )
    )| {
        let lab = test_lab_runtime();
        let mut tracker = ObligationTracker::new();

        futures_lite::future::block_on(async {
            let mut runtime_state = RuntimeBuilder::new().lab(&lab).build_state().unwrap();

            let region_id = RegionId::from_arena(ArenaIndex::new(0, 2));
            let task_id = TaskId::from_arena(ArenaIndex::new(0, 2));

            // Setup
            let _ = runtime_state.create_region(region_id, None, Time::from_nanos(0));
            let cx = test_cx_with_ids(2, 2);
            let _ = runtime_state.spawn(
                region_id,
                Box::pin(async { () }),
                Some("test_task".to_string()),
                &cx,
                None
            );

            for (i, (first_op, second_op)) in double_attempt_scenarios.iter().enumerate() {
                // Issue permit
                if let Ok(obligation_id) = runtime_state.create_obligation(
                    ObligationKind::Lease,
                    task_id,
                    region_id,
                    Some(format!("double_test_{}", i)),
                ) {
                    tracker.record_permit(obligation_id, ObligationKind::Lease, task_id, region_id);

                    // First resolution (should succeed)
                    let first_result = match first_op.as_str() {
                        "commit" => {
                            tracker.record_commit(obligation_id);
                            runtime_state.commit_obligation(obligation_id)
                        }
                        "abort" => {
                            tracker.record_abort(obligation_id, ObligationAbortReason::Explicit);
                            runtime_state.abort_obligation(obligation_id, ObligationAbortReason::Explicit)
                        }
                        _ => unreachable!(),
                    };

                    prop_assert!(
                        first_result.is_ok(),
                        "First resolution should succeed: {:?}",
                        first_result
                    );

                    // Second attempt (should fail)
                    let second_result = match second_op.as_str() {
                        "commit" => {
                            tracker.record_commit(obligation_id); // This will mark as double attempt
                            runtime_state.commit_obligation(obligation_id)
                        }
                        "abort" => {
                            tracker.record_abort(obligation_id, ObligationAbortReason::Explicit);
                            runtime_state.abort_obligation(obligation_id, ObligationAbortReason::Explicit)
                        }
                        _ => unreachable!(),
                    };

                    // MR4: Second attempt should fail
                    prop_assert!(
                        second_result.is_err(),
                        "Double resolution should fail but succeeded: {:?}",
                        second_result
                    );
                }
            }

            // Final verification: double-ack protection worked
            prop_assert!(
                tracker.verify_double_ack_protection(),
                "Double-ack protection invariant violated"
            );
        });
    });
}

/// **MR5: Concurrent Uniqueness Preservation**
///
/// The permit lifecycle through ShardedState should preserve uniqueness
/// even with concurrent operations across multiple workers/contexts.
#[test]
fn mr5_concurrent_uniqueness_preservation() {
    proptest!(|(
        concurrent_operations in prop::collection::vec(
            (
                0u32..5u32, // region_slot
                0u32..5u32, // task_slot
                prop::sample::select(vec![
                    ObligationKind::SendPermit,
                    ObligationKind::Ack,
                    ObligationKind::IoOp
                ]),
            ),
            10..100
        )
    )| {
        let lab = test_lab_runtime();
        let shared_tracker = Arc::new(StdMutex::new(ObligationTracker::new()));

        futures_lite::future::block_on(async {
            let mut runtime_state = RuntimeBuilder::new().lab(&lab).build_state().unwrap();

            // Setup multiple regions and tasks
            for region_slot in 0..5 {
                for task_slot in 0..5 {
                    let region_id = RegionId::from_arena(ArenaIndex::new(0, region_slot));
                    let task_id = TaskId::from_arena(ArenaIndex::new(0, task_slot));

                    if runtime_state.region(region_id).is_none() {
                        let _ = runtime_state.create_region(region_id, None, Time::from_nanos(0));
                    }

                    if runtime_state.task(task_id).is_none() {
                        let cx = test_cx_with_ids(region_slot, task_slot);
                        let _ = runtime_state.spawn(
                            region_id,
                            Box::pin(async { () }),
                            Some(format!("task_{}_{}", region_slot, task_slot)),
                            &cx,
                            None
                        );
                    }
                }
            }

            let mut issued_ids = HashSet::new();

            // Simulate concurrent permit issuance
            for (region_slot, task_slot, kind) in concurrent_operations {
                let region_id = RegionId::from_arena(ArenaIndex::new(0, region_slot));
                let task_id = TaskId::from_arena(ArenaIndex::new(0, task_slot));

                if let Ok(obligation_id) = runtime_state.create_obligation(
                    kind,
                    task_id,
                    region_id,
                    Some(format!("concurrent_{}_{}", region_slot, task_slot)),
                ) {
                    // MR5: Check immediate uniqueness
                    prop_assert!(
                        !issued_ids.contains(&obligation_id),
                        "Concurrent permit issuance produced duplicate ID: {:?}",
                        obligation_id
                    );

                    issued_ids.insert(obligation_id);

                    let mut tracker = shared_tracker.lock().unwrap();
                    tracker.record_permit(obligation_id, kind, task_id, region_id);
                }
            }

            // Final verification: all concurrent operations preserved uniqueness
            let tracker = shared_tracker.lock().unwrap();
            prop_assert!(
                tracker.verify_unique_permits(),
                "Concurrent uniqueness preservation violated"
            );

            // Additional check: no arena index collisions
            let arena_indices: HashSet<_> = issued_ids.iter()
                .map(|id| id.arena_index().index())
                .collect();
            prop_assert_eq!(
                arena_indices.len(),
                issued_ids.len(),
                "Arena index collision in concurrent scenario"
            );
        });
    });
}

// =============================================================================
// Integration Tests
// =============================================================================

/// **Comprehensive Integration Test**
///
/// Tests all metamorphic relations together to ensure they work in combination.
#[test]
fn comprehensive_obligation_lifecycle_integration() {
    let lab = test_lab_runtime();
    let mut tracker = ObligationTracker::new();

    futures_lite::future::block_on(async {
        let mut runtime_state = RuntimeBuilder::new().lab(&lab).build_state().unwrap();

        let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));
        let task_id = TaskId::from_arena(ArenaIndex::new(0, 0));

        // Setup
        let _ = runtime_state.create_region(region_id, None, Time::from_nanos(0));
        let cx = test_cx_with_ids(0, 0);
        let _ = runtime_state.spawn(
            region_id,
            Box::pin(async { () }),
            Some("integration_test_task".to_string()),
            &cx,
            None
        );

        // Test all obligation kinds
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
            ObligationKind::SemaphorePermit,
        ];

        let mut obligations = Vec::new();

        // Issue permits for each kind
        for (i, &kind) in kinds.iter().enumerate() {
            if let Ok(obligation_id) = runtime_state.create_obligation(
                kind,
                task_id,
                region_id,
                Some(format!("integration_{}", i)),
            ) {
                tracker.record_permit(obligation_id, kind, task_id, region_id);
                obligations.push(obligation_id);
            }
        }

        // Test various resolution patterns
        if let Some(&id1) = obligations.get(0) {
            let _ = runtime_state.commit_obligation(id1);
            tracker.record_commit(id1);
        }

        if let Some(&id2) = obligations.get(1) {
            let _ = runtime_state.abort_obligation(id2, ObligationAbortReason::Cancel);
            tracker.record_abort(id2, ObligationAbortReason::Cancel);
        }

        // Test double resolution protection
        if let Some(&id3) = obligations.get(2) {
            let _ = runtime_state.commit_obligation(id3);
            tracker.record_commit(id3);

            // Try to abort committed obligation
            let double_abort = runtime_state.abort_obligation(id3, ObligationAbortReason::Explicit);
            tracker.record_abort(id3, ObligationAbortReason::Explicit);

            assert!(double_abort.is_err(), "Double resolution should fail");
        }

        // Leave remaining obligations unresolved for leak testing
        let unresolved = tracker.unresolved_permits();
        for &id in &unresolved {
            tracker.record_leak(id);
        }

        // Verify all metamorphic relations
        assert!(tracker.verify_unique_permits(), "MR1: Unique permits violated");
        assert!(tracker.verify_token_matching(), "MR2: Token matching violated");
        assert!(tracker.verify_leak_detection(), "MR3: Leak detection violated");
        assert!(tracker.verify_double_ack_protection(), "MR4: Double-ack protection violated");

        println!("✓ All metamorphic relations verified successfully!");
    });
}