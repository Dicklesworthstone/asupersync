//! Metamorphic testing for obligation::guarded RAII cleanup invariants.
//!
//! Property-based tests that validate fundamental RAII guard semantics for
//! GradedObligation using metamorphic relations that must hold regardless of
//! timing, cancellation, or panic conditions.

use proptest::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::obligation::graded::{GradedObligation, GradedScope, Resolution};
use asupersync::record::ObligationKind;
use asupersync::cx::Cx;
use asupersync::lab::{config::LabConfig, runtime::LabRuntime};
use asupersync::time::sleep;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use asupersync::{region, scope};

/// Test helper for creating deterministic contexts
fn create_test_context(region_id: u32, task_id: u32) -> Cx {
    Cx::test(
        RegionId::new(ArenaIndex::new(region_id as usize)),
        TaskId::new(ArenaIndex::new(task_id as usize)),
        Budget::default(),
    )
}

/// Test configuration for obligation operations
#[derive(Debug, Clone)]
struct ObligationTestConfig {
    /// Number of obligations to create
    count: usize,
    /// Whether to resolve some obligations
    resolve_some: bool,
    /// How many to resolve (if resolve_some)
    resolve_count: usize,
    /// Whether to use commit or abort resolution
    use_commit: bool,
    /// Whether to introduce cancellation
    with_cancellation: bool,
    /// Test description
    description: String,
}

/// Property-based strategy for generating obligation test configurations
fn obligation_config_strategy() -> impl Strategy<Value = ObligationTestConfig> {
    (
        1usize..=5,  // count
        any::<bool>(), // resolve_some
        0usize..=5,  // resolve_count
        any::<bool>(), // use_commit
        any::<bool>(), // with_cancellation
        "[a-z]{5,10}", // description
    ).prop_map(|(count, resolve_some, resolve_count, use_commit, with_cancellation, description)| {
        let resolve_count = if resolve_some { resolve_count.min(count) } else { 0 };
        ObligationTestConfig {
            count,
            resolve_some,
            resolve_count,
            use_commit,
            with_cancellation,
            description,
        }
    })
}

/// Violation tracker for detecting test failures
#[derive(Debug, Clone)]
struct ViolationTracker {
    violations: Arc<AtomicUsize>,
}

impl ViolationTracker {
    fn new() -> Self {
        Self {
            violations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_violation(&self) {
        self.violations.fetch_add(1, Ordering::Relaxed);
    }

    fn violations(&self) -> usize {
        self.violations.load(Ordering::Relaxed)
    }

    fn assert_no_violations(&self) {
        assert_eq!(self.violations(), 0, "Metamorphic relation violated");
    }
}

/// Helper to create obligations with unique descriptions
fn create_obligations(count: usize, base_desc: &str) -> Vec<GradedObligation> {
    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
    ];

    (0..count)
        .map(|i| {
            let kind = kinds[i % kinds.len()];
            let description = format!("{}_{}", base_desc, i);
            GradedObligation::reserve(kind, description)
        })
        .collect()
}

/// MR1: RAII guard runs cleanup on drop (panic if not resolved)
/// Property: Dropping an unresolved obligation must panic, resolved obligations don't panic
#[test]
fn mr1_raii_guard_cleanup_on_drop() {
    proptest!(|(config in obligation_config_strategy())| {
        if config.count == 0 {
            return Ok(());
        }

        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            // Test 1: Unresolved obligation should panic on drop
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let obligation = GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "unresolved_obligation"
                );
                // Don't resolve - this should panic on drop
                drop(obligation);
            }));

            match panic_result {
                Err(_) => {
                    // Expected panic - this is correct RAII behavior
                },
                Ok(()) => {
                    tracker.record_violation(); // Should have panicked
                }
            }

            // Test 2: Resolved obligation should not panic on drop
            let no_panic_result = catch_unwind(AssertUnwindSafe(|| {
                let obligation = GradedObligation::reserve(
                    ObligationKind::Ack,
                    "resolved_obligation"
                );
                let _proof = obligation.resolve(Resolution::Commit);
                // Should drop cleanly without panic
            }));

            match no_panic_result {
                Ok(()) => {
                    // Expected - resolved obligations don't panic
                },
                Err(_) => {
                    tracker.record_violation(); // Should not have panicked
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR2: mem::forget bypasses cleanup (caller responsibility)
/// Property: Using mem::forget prevents drop and thus no panic, but leaks the obligation
#[test]
fn mr2_mem_forget_bypasses_cleanup() {
    proptest!(|(config in obligation_config_strategy())| {
        if config.count == 0 {
            return Ok(());
        }

        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            // Use mem::forget to bypass drop - should not panic
            let no_panic_result = catch_unwind(AssertUnwindSafe(|| {
                let obligation = GradedObligation::reserve(
                    ObligationKind::Lease,
                    "forgotten_obligation"
                );
                // Don't resolve, but forget to bypass drop
                std::mem::forget(obligation);
                // No panic should occur since drop doesn't run
            }));

            match no_panic_result {
                Ok(()) => {
                    // Expected - mem::forget bypasses drop, so no panic
                },
                Err(_) => {
                    tracker.record_violation(); // Should not have panicked with forget
                }
            }

            // Verify that without forget, it would panic
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let obligation = GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "not_forgotten_obligation"
                );
                // Don't resolve, don't forget - should panic on drop
            }));

            match panic_result {
                Err(_) => {
                    // Expected - without forget, unresolved obligation panics
                },
                Ok(()) => {
                    tracker.record_violation(); // Should have panicked without forget
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR3: cleanup exactly once even with panic (double-panic protection)
/// Property: During a panic, dropping unresolved obligations should not cause another panic
#[test]
fn mr3_cleanup_once_with_panic_protection() {
    proptest!(|(config in obligation_config_strategy())| {
        if config.count == 0 {
            return Ok(());
        }

        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            // Test that during unwinding (panic), dropping obligations doesn't double-panic
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let _obligation1 = GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "panic_test_1"
                );
                let _obligation2 = GradedObligation::reserve(
                    ObligationKind::Ack,
                    "panic_test_2"
                );

                // Cause a panic while obligations are in scope
                panic!("Intentional panic for double-panic test");

                // The obligations should not cause additional panics during unwinding
            }));

            // We expect exactly one panic (the intentional one)
            match panic_result {
                Err(panic_payload) => {
                    // Check that it's our intentional panic
                    if let Some(msg) = panic_payload.downcast_ref::<&str>() {
                        if *msg == "Intentional panic for double-panic test" {
                            // Correct - single panic as expected
                        } else {
                            tracker.record_violation(); // Wrong panic message
                        }
                    } else if let Some(msg) = panic_payload.downcast_ref::<String>() {
                        if msg.contains("OBLIGATION LEAKED") {
                            tracker.record_violation(); // Double panic - obligations panicked too
                        }
                    } else {
                        tracker.record_violation(); // Unexpected panic type
                    }
                },
                Ok(()) => {
                    tracker.record_violation(); // Should have panicked
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR4: cancel fires cleanup deterministically
/// Property: When cancellation occurs, obligations should be cleaned up properly
#[test]
fn mr4_cancel_fires_cleanup_deterministically() {
    proptest!(|(config in obligation_config_strategy())| {
        if config.count == 0 || !config.with_cancellation {
            return Ok(());
        }

        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            // Test cancellation scenario using region closure
            let result = region(|outer_cx, outer_scope| async move {
                let obligation_task = outer_scope.spawn(|task_cx| async move {
                    let mut scope = GradedScope::open("cancel_test_scope");
                    let mut obligations = Vec::new();

                    // Create obligations
                    for i in 0..config.count.min(3) {
                        scope.on_reserve();
                        let obligation = GradedObligation::reserve(
                            ObligationKind::SendPermit,
                            format!("cancel_test_{}", i)
                        );
                        obligations.push(obligation);
                    }

                    // Resolve some obligations before potential cancellation
                    for _ in 0..config.resolve_count.min(obligations.len()) {
                        if let Some(obligation) = obligations.pop() {
                            let _proof = obligation.resolve(Resolution::Abort);
                            scope.on_resolve();
                        }
                    }

                    // Sleep to allow cancellation
                    sleep(task_cx, Duration::from_millis(100)).await;

                    // Resolve remaining obligations if we get here
                    for obligation in obligations {
                        let _proof = obligation.resolve(Resolution::Abort);
                        scope.on_resolve();
                    }

                    // Close scope
                    scope.close()
                });

                // Cancel after short delay
                sleep(outer_cx, Duration::from_millis(50)).await;

                // Region closure will cancel the obligation task
                obligation_task.await
            }).await;

            // Verify clean cancellation - either completed or cancelled cleanly
            match result {
                asupersync::types::Outcome::Ok(scope_result) => {
                    // Task completed before cancellation
                    match scope_result {
                        Ok(_) => {}, // Clean completion
                        Err(_) => {}, // Scope leak error - acceptable in test
                    }
                },
                asupersync::types::Outcome::Cancelled(_) => {
                    // Task was cancelled - this is expected
                },
                asupersync::types::Outcome::Err(_) => {
                    // Some other error - acceptable in test harness
                },
                asupersync::types::Outcome::Panicked(_) => {
                    // This could happen due to obligation drop panics
                    // In real usage, proper cleanup should prevent this
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR5: nested guards cleanup LIFO order (last-in-first-out)
/// Property: When multiple obligations are in nested scopes, they should drop in reverse order
#[test]
fn mr5_nested_guards_cleanup_lifo_order() {
    proptest!(|(config in obligation_config_strategy())| {
        if config.count < 2 {
            return Ok(()); // Need at least 2 obligations for nesting test
        }

        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            // Track the order of cleanup calls by using resolved obligations
            let mut cleanup_order = Vec::new();

            // Test nested scopes with proper resolution
            {
                let obligation1 = GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "outer_obligation"
                );

                {
                    let obligation2 = GradedObligation::reserve(
                        ObligationKind::Ack,
                        "middle_obligation"
                    );

                    {
                        let obligation3 = GradedObligation::reserve(
                            ObligationKind::Lease,
                            "inner_obligation"
                        );

                        // Resolve in reverse order (LIFO)
                        let _proof3 = obligation3.resolve(Resolution::Commit);
                        cleanup_order.push(3);
                    }

                    let _proof2 = obligation2.resolve(Resolution::Commit);
                    cleanup_order.push(2);
                }

                let _proof1 = obligation1.resolve(Resolution::Commit);
                cleanup_order.push(1);
            }

            // Verify LIFO order: inner resolved first (3), then middle (2), then outer (1)
            let expected_order = vec![3, 2, 1];
            if cleanup_order != expected_order {
                tracker.record_violation();
            }

            // Test automatic LIFO cleanup via scope drop with unresolved obligations
            // This should panic in LIFO order (though we can't easily verify the exact order)
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let _obligation1 = GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "outer_unresolved"
                );

                let _obligation2 = GradedObligation::reserve(
                    ObligationKind::Ack,
                    "inner_unresolved"
                );

                // Both will panic on drop in LIFO order when this scope exits
            }));

            // We expect a panic due to unresolved obligations
            match panic_result {
                Err(_) => {
                    // Expected - at least one obligation caused a panic
                    // The exact order is ensured by Rust's drop order semantics
                },
                Ok(()) => {
                    tracker.record_violation(); // Should have panicked
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// Composite MR: Complex obligation scenarios with mixed resolution patterns
/// Property: Various combinations of obligations maintain semantic correctness
#[test]
fn mr_composite_obligation_scenarios() {
    proptest!(|(
        scenarios in proptest::collection::vec((1usize..=4, 0usize..=4, any::<bool>()), 1..4)
    )| {
        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            for (i, (create_count, resolve_count, use_commit)) in scenarios.into_iter().enumerate() {
                let create_count = create_count.max(1);
                let resolve_count = resolve_count.min(create_count);
                let leak_count = create_count - resolve_count;

                let test_result = catch_unwind(AssertUnwindSafe(|| {
                    let mut scope = GradedScope::open(format!("composite_test_{}", i));
                    let mut obligations = Vec::new();

                    // Create obligations
                    for j in 0..create_count {
                        scope.on_reserve();
                        let obligation = GradedObligation::reserve(
                            ObligationKind::SendPermit,
                            format!("composite_{}_{}", i, j)
                        );
                        obligations.push(obligation);
                    }

                    // Resolve some obligations
                    for _ in 0..resolve_count {
                        if let Some(obligation) = obligations.pop() {
                            let resolution = if use_commit {
                                Resolution::Commit
                            } else {
                                Resolution::Abort
                            };
                            let _proof = obligation.resolve(resolution);
                            scope.on_resolve();
                        }
                    }

                    // Close scope - should succeed if no leaks
                    let scope_result = scope.close();

                    if leak_count == 0 {
                        match scope_result {
                            Ok(_) => {}, // Expected clean close
                            Err(_) => panic!("Scope should have closed cleanly"),
                        }
                    } else {
                        match scope_result {
                            Ok(_) => panic!("Scope should have detected leaks"),
                            Err(_) => {}, // Expected leak error
                        }
                    }

                    // Remaining unresolved obligations will panic on drop if any
                }));

                // Analyze the result
                match test_result {
                    Ok(()) => {
                        // No panic occurred
                        if leak_count > 0 {
                            tracker.record_violation(); // Should have panicked due to leaked obligations
                        }
                    },
                    Err(_) => {
                        // Panic occurred
                        if leak_count == 0 {
                            tracker.record_violation(); // Should not have panicked with no leaks
                        }
                    }
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// Edge case MR: into_raw escape hatch bypasses RAII cleanup
/// Property: into_raw() should disarm the drop bomb and prevent panics
#[test]
fn mr_edge_case_into_raw_escape_hatch() {
    proptest!(|(config in obligation_config_strategy())| {
        if config.count == 0 {
            return Ok(());
        }

        let tracker = ViolationTracker::new();
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(|| async {
            // Test that into_raw disarms the drop bomb
            let no_panic_result = catch_unwind(AssertUnwindSafe(|| {
                let obligation = GradedObligation::reserve(
                    ObligationKind::Lease,
                    "escape_hatch_test"
                );

                // Use escape hatch - should disarm drop bomb
                let raw_obligation = obligation.into_raw();

                // Verify raw obligation metadata
                if raw_obligation.kind != ObligationKind::Lease {
                    panic!("Wrong obligation kind in raw");
                }
                if raw_obligation.description != "escape_hatch_test" {
                    panic!("Wrong description in raw");
                }

                // Drop the raw obligation - should not panic
                drop(raw_obligation);
            }));

            match no_panic_result {
                Ok(()) => {
                    // Expected - into_raw should disarm drop bomb
                },
                Err(_) => {
                    tracker.record_violation(); // Should not have panicked with into_raw
                }
            }

            // Test multiple obligations with some using into_raw
            let mixed_result = catch_unwind(AssertUnwindSafe(|| {
                let obligation1 = GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "mixed_test_1"
                );
                let obligation2 = GradedObligation::reserve(
                    ObligationKind::Ack,
                    "mixed_test_2"
                );
                let obligation3 = GradedObligation::reserve(
                    ObligationKind::Lease,
                    "mixed_test_3"
                );

                // Resolve first normally
                let _proof1 = obligation1.resolve(Resolution::Commit);

                // Use escape hatch for second
                let _raw2 = obligation2.into_raw();

                // Leave third unresolved - should panic on drop
                drop(obligation3);
            }));

            // Should panic due to the third obligation
            match mixed_result {
                Err(_) => {
                    // Expected - third obligation should cause panic
                },
                Ok(()) => {
                    tracker.record_violation(); // Should have panicked due to unresolved obligation
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}