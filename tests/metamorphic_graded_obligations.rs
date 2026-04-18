//! Metamorphic Testing for Graded Obligations System
//!
//! Tests linear type discipline approximation, drop bomb behavior, and scope-based
//! resource tracking in the graded obligations system.
//!
//! Target: src/obligation/graded.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Drop Bomb Consistency**: Uncommitted obligations trigger drop bombs deterministically
//! 2. **Scope Accounting**: Reserve/resolve counts balance across all scope operations
//! 3. **Resolution Idempotence**: Multiple attempts to resolve return consistent state
//! 4. **Resource Conservation**: Total obligations across scopes remain constant during transfers
//! 5. **Zero-Leak Invariant**: All scopes must close with zero outstanding obligations
//! 6. **Proof Token Validity**: Resolved obligations produce valid proof tokens
//! 7. **Raw Escape Safety**: into_raw() disarms drop bombs without triggering panics

#![cfg(test)]

use proptest::prelude::*;
use std::panic;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

// Import from graded obligations system
use asupersync::obligation::graded::{GradedObligation, GradedScope, Resolution};
use asupersync::record::ObligationKind;

/// Metamorphic relation: Drop Bomb Consistency
///
/// Uncommitted obligations must trigger drop bombs deterministically.
/// The same obligation type/description should behave consistently across runs.
#[test]
fn mr_drop_bomb_consistency() {
    proptest!(|(kind in obligation_kind_strategy(), description: String)| {
        let mut bomb_results = Vec::new();

        // Test identical obligation creation/drop 5 times
        for _ in 0..5 {
            let bomb_triggered = test_drop_bomb_behavior(kind, &description);
            bomb_results.push(bomb_triggered);
        }

        // MR: All repetitions should have identical bomb behavior
        let first_result = bomb_results[0];
        for &result in &bomb_results[1..] {
            prop_assert_eq!(result, first_result,
                "Drop bomb behavior inconsistent for {:?} '{}': got different results",
                kind, description);
        }

        // MR: Uncommitted obligations should always trigger bombs
        prop_assert!(first_result,
            "Uncommitted obligation {:?} '{}' should trigger drop bomb", kind, description);
    });
}

/// Metamorphic relation: Scope Accounting
///
/// Tests that reserve/resolve counts balance across all scope operations:
/// outstanding = reserved - resolved (invariant maintained)
#[test]
fn mr_scope_accounting() {
    proptest!(|(operations in prop::collection::vec(any::<u32>(), 1..=20))| {
        let mut scope = GradedScope::open("test_scope");
        let mut expected_reserved = 0u32;
        let mut expected_resolved = 0u32;

        for &op_type in &operations {
            match op_type % 3 {
                0 => {
                    // Reserve operation
                    scope.on_reserve();
                    expected_reserved += 1;
                }
                1 => {
                    // Resolve operation (only if we have reserves)
                    if expected_reserved > expected_resolved {
                        scope.on_resolve();
                        expected_resolved += 1;
                    }
                }
                _ => {
                    // Check outstanding count
                    let actual_outstanding = scope.outstanding();
                    let expected_outstanding = expected_reserved - expected_resolved;
                    prop_assert_eq!(actual_outstanding, expected_outstanding,
                        "Scope accounting invariant violated: outstanding {} ≠ reserved {} - resolved {}",
                        actual_outstanding, expected_reserved, expected_resolved);
                }
            }
        }

        // Final check: accounting should be consistent
        let final_outstanding = scope.outstanding();
        let expected_final = expected_reserved - expected_resolved;
        prop_assert_eq!(final_outstanding, expected_final,
            "Final scope accounting mismatch: {} ≠ {} - {}",
            final_outstanding, expected_reserved, expected_resolved);

        // MR: Close should succeed only if outstanding is zero
        let close_result = scope.close();
        if expected_final == 0 {
            prop_assert!(close_result.is_ok(), "Scope with zero outstanding should close successfully");
            if let Ok(proof) = close_result {
                prop_assert_eq!(proof.total_reserved, expected_reserved,
                    "Proof reserved count mismatch");
                prop_assert_eq!(proof.total_resolved, expected_resolved,
                    "Proof resolved count mismatch");
            }
        } else {
            prop_assert!(close_result.is_err(), "Scope with outstanding obligations should fail to close");
            if let Err(leak_error) = close_result {
                prop_assert_eq!(leak_error.outstanding, expected_final,
                    "Leak error outstanding count mismatch");
            }
        }
    });
}

/// Metamorphic relation: Resolution Idempotence
///
/// Once an obligation is resolved, it should consistently report resolved state
/// and attempting to resolve again should not be possible (moves value).
#[test]
fn mr_resolution_idempotence() {
    proptest!(|(kind in obligation_kind_strategy(), description: String, resolution in resolution_strategy())| {
        let obligation = GradedObligation::reserve(kind, description.clone());

        // MR: Before resolution, obligation should not be resolved
        prop_assert!(!obligation.is_resolved(),
            "New obligation should not be marked as resolved");

        // Resolve the obligation
        let proof = obligation.resolve(resolution);

        // MR: Proof should match the resolution type and kind
        prop_assert_eq!(proof.kind, kind,
            "Proof kind {} does not match obligation kind {}", proof.kind, kind);
        prop_assert_eq!(proof.resolution, resolution,
            "Proof resolution {:?} does not match requested {:?}", proof.resolution, resolution);

        // MR: Proof should display correctly
        let proof_string = format!("{}", proof);
        prop_assert!(proof_string.contains(&kind.to_string()),
            "Proof display should contain kind");
        prop_assert!(proof_string.contains(&resolution.to_string()),
            "Proof display should contain resolution");

        // Note: We cannot test obligation.is_resolved() after resolve() because
        // resolve() consumes the obligation (move semantics), which is the correct
        // behavior for preventing double-resolution.
    });
}

/// Metamorphic relation: Resource Conservation
///
/// When transferring obligations between scopes or resolving them,
/// total obligation count should be conserved (creation/resolution balance).
#[test]
fn mr_resource_conservation() {
    proptest!(|(obligation_count in 1usize..=10, resolve_count in 0usize..=10)| {
        let resolve_count = resolve_count.min(obligation_count); // Can't resolve more than created
        let mut scope = GradedScope::open("conservation_test");

        // Phase 1: Create obligations and record reserves
        let mut obligations = Vec::new();
        for i in 0..obligation_count {
            let obligation = GradedObligation::reserve(
                ObligationKind::SendPermit,
                format!("test_obligation_{}", i)
            );
            scope.on_reserve();
            obligations.push(obligation);
        }

        // MR: Total reserved should equal created obligations
        prop_assert_eq!(scope.outstanding(), obligation_count as u32,
            "Outstanding count {} should equal created obligations {}",
            scope.outstanding(), obligation_count);

        // Phase 2: Resolve some obligations
        let mut resolved_proofs = Vec::new();
        let mut remaining_obligations = Vec::new();

        for (i, obligation) in obligations.into_iter().enumerate() {
            if i < resolve_count {
                let proof = obligation.resolve(Resolution::Commit);
                scope.on_resolve();
                resolved_proofs.push(proof);
            } else {
                remaining_obligations.push(obligation);
            }
        }

        // MR: Outstanding should equal created - resolved
        let expected_outstanding = obligation_count - resolve_count;
        prop_assert_eq!(scope.outstanding(), expected_outstanding as u32,
            "After resolution, outstanding {} should equal {} - {}",
            scope.outstanding(), obligation_count, resolve_count);

        // MR: Resolved proofs should all be valid
        for (i, proof) in resolved_proofs.iter().enumerate() {
            prop_assert_eq!(proof.kind, ObligationKind::SendPermit,
                "Proof {} should have correct kind", i);
            prop_assert_eq!(proof.resolution, Resolution::Commit,
                "Proof {} should have correct resolution", i);
        }

        // MR: Conservation law - if outstanding is zero, scope should close cleanly
        if expected_outstanding == 0 {
            let close_result = scope.close();
            prop_assert!(close_result.is_ok(),
                "Scope with zero outstanding should close successfully");
        } else {
            // Clean up remaining obligations to avoid drop bombs
            for remaining in remaining_obligations {
                let _proof = remaining.resolve(Resolution::Abort);
                scope.on_resolve();
            }
            // Now scope should close cleanly
            let close_result = scope.close();
            prop_assert!(close_result.is_ok(),
                "Scope should close after cleanup");
        }
    });
}

/// Metamorphic relation: Zero-Leak Invariant
///
/// All scopes must close with zero outstanding obligations.
/// Any scope with outstanding obligations should fail to close with an error.
#[test]
fn mr_zero_leak_invariant() {
    proptest!(|(reserve_count in 0u32..=20, resolve_ratio in 0.0f64..=1.0)| {
        let mut scope = GradedScope::open("leak_test");
        let resolve_count = ((reserve_count as f64) * resolve_ratio).floor() as u32;

        // Reserve obligations
        for _ in 0..reserve_count {
            scope.on_reserve();
        }

        // Resolve some obligations
        for _ in 0..resolve_count {
            scope.on_resolve();
        }

        let outstanding = scope.outstanding();
        let expected_outstanding = reserve_count - resolve_count;

        // MR: Outstanding count should match expected
        prop_assert_eq!(outstanding, expected_outstanding,
            "Outstanding count {} != expected {}", outstanding, expected_outstanding);

        // MR: Close behavior should depend on outstanding count
        let close_result = scope.close();

        if expected_outstanding == 0 {
            // Should close successfully with zero outstanding
            prop_assert!(close_result.is_ok(),
                "Scope with zero outstanding ({}) should close successfully", expected_outstanding);

            if let Ok(proof) = close_result {
                prop_assert_eq!(proof.total_reserved, reserve_count,
                    "Proof reserved count mismatch");
                prop_assert_eq!(proof.total_resolved, resolve_count,
                    "Proof resolved count mismatch");
                prop_assert!(proof.label == "leak_test",
                    "Proof label should match scope label");
            }
        } else {
            // Should fail to close with leak error
            prop_assert!(close_result.is_err(),
                "Scope with {} outstanding should fail to close", expected_outstanding);

            if let Err(leak_error) = close_result {
                prop_assert_eq!(leak_error.outstanding, expected_outstanding,
                    "Leak error outstanding count mismatch");
                prop_assert_eq!(leak_error.reserved, reserve_count,
                    "Leak error reserved count mismatch");
                prop_assert_eq!(leak_error.resolved, resolve_count,
                    "Leak error resolved count mismatch");
                prop_assert!(leak_error.label == "leak_test",
                    "Leak error label should match scope label");
            }
        }
    });
}

/// Metamorphic relation: Proof Token Validity
///
/// Resolved obligations should produce valid proof tokens that accurately
/// reflect the original obligation and resolution type.
#[test]
fn mr_proof_token_validity() {
    proptest!(|(kind in obligation_kind_strategy(), description: String, resolution in resolution_strategy())| {
        let obligation = GradedObligation::reserve(kind, description.clone());

        // Record original properties
        let original_kind = obligation.kind();
        let original_description = obligation.description().to_string();
        let original_resolved = obligation.is_resolved();

        // MR: Pre-resolution state should be unresolved
        prop_assert!(!original_resolved, "New obligation should not be resolved");
        prop_assert_eq!(original_kind, kind, "Kind should match");
        prop_assert_eq!(original_description, description, "Description should match");

        // Resolve the obligation
        let proof = obligation.resolve(resolution);

        // MR: Proof should faithfully represent the resolution
        prop_assert_eq!(proof.kind, original_kind,
            "Proof kind {} should match original {}", proof.kind, original_kind);
        prop_assert_eq!(proof.resolution, resolution,
            "Proof resolution {:?} should match requested {:?}", proof.resolution, resolution);

        // MR: Proof should be displayable and contain relevant information
        let proof_display = format!("{}", proof);
        prop_assert!(proof_display.len() > 0, "Proof should have non-empty display");

        // MR: Proof should implement Debug correctly
        let proof_debug = format!("{:?}", proof);
        prop_assert!(proof_debug.len() > 0, "Proof should have non-empty debug representation");

        // MR: Proof should be cloneable and equality should work
        let proof_clone = proof.clone();
        prop_assert_eq!(proof, proof_clone, "Proof should be cloneable and equal to clone");
    });
}

/// Metamorphic relation: Raw Escape Safety
///
/// The into_raw() escape hatch should disarm drop bombs without triggering panics,
/// and should preserve obligation metadata in the resulting RawObligation.
#[test]
fn mr_raw_escape_safety() {
    proptest!(|(kind in obligation_kind_strategy(), description: String)| {
        let obligation = GradedObligation::reserve(kind, description.clone());

        // Record original properties
        let original_kind = obligation.kind();
        let original_description = obligation.description().to_string();

        // MR: into_raw should not panic and should produce valid RawObligation
        let raw_obligation = obligation.into_raw();

        // MR: Raw obligation should preserve original metadata
        prop_assert_eq!(raw_obligation.kind, original_kind,
            "Raw obligation kind {} should match original {}", raw_obligation.kind, original_kind);
        prop_assert_eq!(&raw_obligation.description, &original_description,
            "Raw obligation description should match original");

        // MR: Raw obligation should be debuggable
        let debug_str = format!("{:?}", raw_obligation);
        prop_assert!(debug_str.len() > 0, "Raw obligation should have non-empty debug representation");

        // MR: Raw obligation should be cloneable
        let raw_clone = raw_obligation.clone();
        prop_assert_eq!(raw_clone.kind, raw_obligation.kind,
            "Cloned raw obligation should have same kind");

        // MR: Dropping raw obligation should not panic (no drop bomb)
        drop(raw_obligation);
        drop(raw_clone);
        // If we reach here, no panic occurred - the test passes

        // Note: We cannot test the original obligation after into_raw() because
        // into_raw() consumes it (move semantics), which prevents double-use.
    });
}

// Helper Functions

/// Test helper for drop bomb behavior
fn test_drop_bomb_behavior(kind: ObligationKind, description: &str) -> bool {
    let _bomb_triggered = Arc::new(AtomicBool::new(false));

    // Use panic::catch_unwind to capture the drop bomb panic
    let panic_result = panic::catch_unwind(|| {
        let _obligation = GradedObligation::reserve(kind, description);
        // Drop without resolving - should trigger drop bomb
    });

    // If panic occurred, bomb was triggered
    panic_result.is_err()
}

// Test Support Types

#[derive(Debug)]
struct ObligationTracker {
    created_count: u32,
    resolved_count: u32,
    dropped_count: u32,
}

impl ObligationTracker {
    fn new() -> Self {
        Self {
            created_count: 0,
            resolved_count: 0,
            dropped_count: 0,
        }
    }

    fn track_creation(&mut self) {
        self.created_count += 1;
    }

    fn track_resolution(&mut self) {
        self.resolved_count += 1;
    }

    fn track_drop(&mut self) {
        self.dropped_count += 1;
    }

    fn outstanding(&self) -> u32 {
        self.created_count
            .saturating_sub(self.resolved_count + self.dropped_count)
    }
}

// Property test generation strategies

fn obligation_kind_strategy() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
        Just(ObligationKind::SemaphorePermit),
    ]
}

fn resolution_strategy() -> impl Strategy<Value = Resolution> {
    prop_oneof![Just(Resolution::Commit), Just(Resolution::Abort),]
}

// Additional integration tests for complex scenarios

#[test]
fn metamorphic_graded_obligations_integration() {
    proptest!(|(operation_count in 5usize..=15, kinds in prop::collection::vec(obligation_kind_strategy(), 5..=15))| {
        let mut scope = GradedScope::open("integration_test");
        let mut tracker = ObligationTracker::new();
        let mut active_obligations = Vec::new();

        // Create obligations
        for (i, kind) in kinds.iter().take(operation_count).enumerate() {
            let obligation = GradedObligation::reserve(*kind, format!("obligation_{}", i));
            scope.on_reserve();
            tracker.track_creation();
            active_obligations.push(obligation);
        }

        // Test different resolution strategies
        let half_count = operation_count / 2;

        // First half: Test into_raw escape hatch
        for i in 0..half_count {
            if let Some(obligation) = active_obligations.pop() {
                let _raw = obligation.into_raw();
                tracker.track_drop();
                // Important: into_raw means the obligation is "handled" but not
                // counted as resolved by the scope, so we need to manually
                // call on_resolve to balance the scope accounting
                scope.on_resolve();
            }
        }

        // Second half: Normal resolution
        while let Some(obligation) = active_obligations.pop() {
            let resolution = if active_obligations.len() % 2 == 0 {
                Resolution::Commit
            } else {
                Resolution::Abort
            };
            let _proof = obligation.resolve(resolution);
            scope.on_resolve();
            tracker.track_resolution();
        }

        // MR: After processing all obligations, scope should have zero outstanding
        let scope_outstanding = scope.outstanding();
        prop_assert_eq!(scope_outstanding, 0,
            "After processing all obligations, scope should have zero outstanding");

        // MR: All obligations should be accounted for by tracker
        let total_tracker_ops = tracker.resolved_count + tracker.dropped_count;
        prop_assert_eq!(total_tracker_ops, tracker.created_count,
            "Tracker should account for all created obligations");

        // MR: Scope should close successfully
        let close_result = scope.close();
        prop_assert!(close_result.is_ok(),
            "Scope should close successfully after all obligations processed");
    });
}
